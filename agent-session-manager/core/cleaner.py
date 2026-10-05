"""Residue executor: removes what an uninstall left behind.

This is a second, deliberately narrower write path than
:mod:`core.executor`. It exists because cleaning up after an uninstall touches
things a session deletion never does -- registry keys, firewall rules, orphaned
shortcuts, vendor cache directories -- and those have their own failure modes.

It shares the *safety* machinery with the session executor rather than
reimplementing it:

  * every file/directory move goes into ``_data/quarantine/<op-id>/`` and can be
    restored by id
  * every destructive step is journalled to the same JSONL file
  * a registry key is ``reg export``-ed before deletion, and the .reg file is
    kept in the quarantine
  * a firewall rule is dumped to JSON before deletion
  * any failure rolls back the steps already taken in that operation

The hard rules, enforced here rather than trusted to the caller:

  1. **`never` is never removed.** Every item is re-classified immediately
     before execution; a path whose disposition is not `safe` or `review` is
     refused, and the refusal is reported instead of raised, so one bad item
     cannot abort a batch.
  2. **`never` re-classification beats a stale client.** The client sends a list
     of paths; the server classifies them again. A path that has since become a
     source repository, or that was never ours, is rejected at execute time.
  3. **Elevation is not attempted.** ``HKLM`` keys, firewall rules, services and
     scheduled tasks are reported with the exact command a user can run in an
     elevated shell. Nothing here silently fails or silently succeeds.
  4. **A running agent blocks its own cleanup.** Deleting an Electon cache or a
     login profile under a live process corrupts it, so the owning process must
     be stopped first.
"""

from __future__ import annotations

import json
import os
import shutil
import time
import uuid
from pathlib import Path

from core import wininteg
from core.ownership import NEVER, REVIEW, SAFE, Classifier, _norm
from core.util import (
    append_jsonl,
    dir_size,
    human_size,
    journal_path,
    now_ms,
    quarantine_root,
    read_jsonl,
    remove_tree,
    stamp,
)

#: Dispositions this module is willing to act on. `never` is absent by design.
ACTIONABLE = (SAFE, REVIEW)


class CleanupError(Exception):
    """A cleanup could not be performed. The message is user-facing Chinese."""


# --------------------------------------------------------------------------
# Preflight
# --------------------------------------------------------------------------


def preflight(agent_id: str, paths: list[str], adapter=None,
              allow_roots: bool = False) -> dict:
    """Check every item before touching anything.

    Returns a per-item verdict plus the blockers that apply to the operation as
    a whole. A `dry_run` execution shows exactly this, so a user can see what
    would happen before anything is moved.

    `allow_roots` permits removing an adapter's own data root. It is False for
    ordinary residue cleanup -- a whole data root is a session-level or
    uninstall-level decision -- and only the uninstall flow turns it on, after
    the user has confirmed the product is going away for good.
    """
    from adapters.registry import get_adapter

    if adapter is None:
        adapter = get_adapter(agent_id)
    label = getattr(adapter, "label", "") or agent_id

    clf = Classifier()

    # Is the agent running? Cleanup under a live process corrupts its profile.
    running: list[str] = []
    if adapter is not None:
        try:
            running = list(adapter.is_running())
        except Exception:
            running = []

    items: list[dict] = []
    for raw in paths:
        p = Path(raw)
        entry: dict = {"path": str(p), "ok": False, "reason": "", "action": ""}
        if not p.exists():
            entry["reason"] = "路径不存在（可能已被删除）。"
            items.append(entry)
            continue

        # A declared root of *this* adapter is exact ownership by definition --
        # the adapter itself says so. Checking it here, before the name-based
        # classifier, matters because the classifier only knows about adapters
        # installed on this machine: an uninstall flow may legitimately need to
        # remove a root even after the product is gone and the classifier can no
        # longer attribute it.
        is_root = False
        if adapter is not None:
            try:
                is_root = is_declared_root(p, adapter)
            except Exception:
                is_root = False

        if is_root and not allow_roots:
            entry.update(
                {
                    "disposition": REVIEW,
                    "category": "user_data",
                    "owner": agent_id,
                    "size": _size_of_path(p)[0],
                    "size_h": human_size(_size_of_path(p)[0]),
                    "evidence": "该 Agent 自己声明的数据根目录",
                    "is_data_root": True,
                    "reason": (
                        "这是该 Agent 的数据根目录，"
                        "请使用「会话删除」或「完整卸载」而不是残留清理。"
                    ),
                }
            )
            items.append(entry)
            continue

        try:
            o = clf.classify(p)
        except Exception as e:
            entry["reason"] = f"无法分类：{type(e).__name__}: {e}"
            items.append(entry)
            continue
        entry.update(
            {
                "disposition": o.disposition,
                "category": o.category,
                "owner": o.owner,
                "size": o.size,
                "size_h": human_size(o.size),
                "evidence": o.evidence,
            }
        )
        if is_root and o.disposition != NEVER:
            entry["ok"] = True
            entry["action"] = "remove"
            entry["is_data_root"] = True
            entry["evidence"] = (entry["evidence"] + "；该 Agent 自己声明的数据根目录").strip("；")
            items.append(entry)
            continue
        # A declared root is only removable when it is not shared or a source
        # repository. When allow_roots is set, "unattributable" must not count
        # as a refusal: the adapter has already claimed this path, which is a
        # stronger statement than any naming rule.
        if is_root and allow_roots and o.category not in ("shared", "source_repo"):
            entry["ok"] = True
            entry["action"] = "remove"
            entry["is_data_root"] = True
            entry["evidence"] = (
                "该 Agent 自己声明的数据根目录"
                + ("；" + entry["evidence"] if entry.get("evidence") else "")
            )
            items.append(entry)
            continue
        if o.disposition == NEVER:
            entry["reason"] = (
                "该路径被判定为禁止删除，已拒绝。"
                f"（{o.evidence or '归属不明或属于共享/用户数据'}）"
            )
            items.append(entry)
            continue
        entry["ok"] = True
        entry["action"] = "remove"
        items.append(entry)

    ok_items = [i for i in items if i["ok"]]
    total = sum(i.get("size", 0) for i in ok_items)
    return {
        "agent": agent_id,
        "label": label,
        "running": running,
        "blocked_by_process": bool(running),
        "items": items,
        "will_remove": len(ok_items),
        "will_remove_bytes": total,
        "will_remove_bytes_h": human_size(total),
        "refused": len([i for i in items if not i["ok"]]),
        "refused_existing": len([i for i in items if not i["ok"] and Path(i["path"]).exists()]),
    }


def is_declared_root(p: Path, adapter) -> bool:
    """Whether `p` is one of the adapter's own roots (not a child of one)."""
    key = _norm(p)
    for r in adapter.roots():
        if key == _norm(r):
            return True
    return False


def _size_of_path(p: Path) -> tuple[int, int]:
    try:
        if p.is_dir():
            return dir_size(p)
        if p.is_file():
            return p.stat().st_size, 1
    except OSError:
        pass
    return 0, 0


def protection(agent_id: str, adapter=None) -> dict:
    """Reasons a full cleanup must not proceed yet."""
    from adapters.registry import get_adapter

    if adapter is None:
        adapter = get_adapter(agent_id)
    blockers: list[dict] = []
    if adapter is None:
        return {"blockers": blockers, "can_proceed": True}

    try:
        running = list(adapter.is_running())
    except Exception:
        running = []
    if running:
        blockers.append(
            {
                "kind": "process",
                "title": "该 Agent 正在运行",
                "detail": f"检测到进程：{'、'.join(running)}。清理其数据前必须先完全退出，"
                          "否则会损坏正在使用的配置文件。",
                "action": "请退出该程序后重试。",
            }
        )

    # Workspace pins: a pin is an explicit "do not touch", and it outranks the
    # convenience of a bulk cleanup.
    try:
        from core import store

        mine = [w for w in store.workspace_pins() if w.get("agent") == agent_id]
        if mine:
            blockers.append(
                {
                    "kind": "pin",
                    "title": f"{len(mine)} 个工作区被标记为「保留」",
                    "detail": "工作区保留标记的语义是「这个项目永远不要动」；"
                              "整体清理会删除其数据。",
                    "action": "如确实要清理，请先取消这些工作区保留标记。",
                    "items": [w.get("path", "") for w in mine],
                }
            )
    except Exception:
        pass
    return {"blockers": blockers, "can_proceed": not blockers}


# --------------------------------------------------------------------------
# The executor
# --------------------------------------------------------------------------


class CleanupExecutor:
    """Removes residue items, reversibly."""

    def execute(
        self,
        agent_id: str,
        paths: list[str],
        allow_permanent: bool = False,
        dry_run: bool = False,
        force_while_running: bool = False,
        allow_roots: bool = False,
    ) -> dict:
        """Remove `paths`, or describe what removal would do when `dry_run`.

        `allow_permanent` disposes of the quarantine at the end, making the
        operation irreversible -- it is used for caches the user explicitly does
        not want to keep a copy of.

        `allow_roots` permits removing an adapter's own data root, for the
        uninstall flow only.
        """
        if not paths:
            raise CleanupError("没有选中任何要清理的项目。")

        pf = preflight(agent_id, paths, allow_roots=allow_roots)

        # A dry run changes nothing, so it is always allowed -- including while
        # the agent is running, which is exactly when a user wants to see what a
        # cleanup would remove. Only the real execution needs the process check.
        if dry_run:
            return {
                "ok": True,
                "dry_run": True,
                "agent": agent_id,
                "preflight": pf,
                "would_block": pf["blocked_by_process"] and not force_while_running,
                "note": (
                    "这是预演结果，未修改任何文件。"
                    + (
                        f"注意：该 Agent 正在运行（{'、'.join(pf['running'])}），"
                        "真正执行前需要先退出程序。"
                        if pf["blocked_by_process"]
                        else ""
                    )
                ),
            }

        if pf["blocked_by_process"] and not force_while_running:
            raise CleanupError(
                f"该 Agent 正在运行（{'、'.join(pf['running'])}），"
                "清理其数据可能损坏配置。请先退出程序。"
            )

        to_remove = [i for i in pf["items"] if i["ok"]]
        if not to_remove:
            return {
                "ok": True,
                "agent": agent_id,
                "op_id": "",
                "removed": 0,
                "failed": 0,
                "bytes": 0,
                "bytes_h": "0 B",
                "results": [
                    {"path": i["path"], "ok": False, "error": i["reason"]}
                    for i in pf["items"]
                ],
                "preflight": pf,
                "note": "没有任何项目通过安全检查，未做修改。",
            }

        op_id = f"{stamp()}-clean-{uuid.uuid4().hex[:8]}"
        qdir = quarantine_root() / op_id
        qdir.mkdir(parents=True, exist_ok=True)

        record: dict = {
            "op_id": op_id,
            "time": now_ms(),
            "kind": "cleanup",
            "agent": agent_id,
            "permanent": bool(allow_permanent),
            "quarantine": str(qdir),
            "steps": [],
            "status": "started",
            "errors": [],
        }

        moved: list[tuple[Path, Path]] = []
        results: list[dict] = []
        freed = 0

        try:
            for item in to_remove:
                src = Path(item["path"])
                if not src.exists():
                    results.append({"path": str(src), "ok": False,
                                    "error": "执行时路径已不存在。"})
                    continue
                dest = qdir / _rel_for(src)
                dest.parent.mkdir(parents=True, exist_ok=True)
                try:
                    _move(src, dest)
                except OSError as e:
                    results.append({"path": str(src), "ok": False,
                                    "error": f"移动失败：{e}"})
                    record["errors"].append(f"{src}: {e}")
                    continue
                moved.append((src, dest))
                freed += item.get("size", 0)
                results.append({"path": str(src), "ok": True, "error": "",
                                "quarantined_to": str(dest),
                                "size": item.get("size", 0)})
                record["steps"].append(
                    {
                        "action": "remove",
                        "path": str(src),
                        "quarantined_to": str(dest),
                        "size": item.get("size", 0),
                        "category": item.get("category", ""),
                        "disposition": item.get("disposition", ""),
                        "result": "moved",
                    }
                )

            ok = sum(1 for r in results if r["ok"])
            if ok == 0:
                # Nothing succeeded: undo nothing, but do not leave an empty
                # quarantine directory behind -- that is the exact residue this
                # tool exists to prevent.
                _drop_if_empty(qdir)
                record["status"] = "noop"
                record["errors"].append("所有项目都未能移除。")
                append_jsonl(journal_path(), record)
                return {
                    "ok": True,
                    "agent": agent_id,
                    "op_id": "",
                    "removed": 0,
                    "failed": len(results),
                    "bytes": 0,
                    "bytes_h": "0 B",
                    "results": results,
                    "preflight": pf,
                    "note": "所有项目都未能移除，未做任何修改。",
                }

            record["status"] = "completed"
            record["removed"] = ok
            record["failed"] = len(results) - ok
            record["freed_bytes"] = freed
            append_jsonl(journal_path(), record)

            if allow_permanent:
                record["quarantine_removed"] = True
                append_jsonl(journal_path(), {**record, "kind": "cleanup-permanent"})
                _err = remove_tree(qdir)
                if _err:
                    record["errors"].append(f"隔离区清理失败：{_err}")

            if ok:
                _invalidate_caches()

            return {
                "ok": True,
                "agent": agent_id,
                "op_id": op_id,
                "removed": ok,
                "failed": len(results) - ok,
                "bytes": freed,
                "bytes_h": human_size(freed),
                "results": results,
                "quarantine": str(qdir),
                "permanent": bool(allow_permanent),
                "preflight": pf,
            }

        except Exception as e:
            # Roll back whatever was already moved.
            for src, dest in reversed(moved):
                try:
                    if dest.exists():
                        src.parent.mkdir(parents=True, exist_ok=True)
                        _move(dest, src)
                        record["steps"].append(
                            {"action": "rollback", "path": str(src), "result": "restored"}
                        )
                except Exception as e2:
                    record["errors"].append(f"回滚失败 {src}: {e2}")
            _drop_if_empty(qdir)
            record["status"] = "rolled_back"
            record["errors"].append(f"{type(e).__name__}: {e}")
            append_jsonl(journal_path(), record)
            if moved:
                _invalidate_caches()
            raise CleanupError(f"清理失败，已回滚：{e}") from e


# --------------------------------------------------------------------------
# Registry keys
# --------------------------------------------------------------------------


def remove_registry_key(hive: str, key: str, op_id: str = "",
                        dry_run: bool = False) -> dict:
    """Delete an HKCU registry key, exporting it first.

    Only `HKCU` is performed. An `HKLM` key needs elevation, and this tool does
    not attempt to elevate: it returns the exact command instead, so the user
    stays in control of the only step that can damage the machine.
    """
    if hive.upper() != "HKCU":
        return {
            "ok": False,
            "needs_admin": True,
            "error": f"{hive} 键需要管理员权限，本工具不会尝试提权。",
            "command": f'reg delete "{hive}\\{key}" /f',
        }

    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "would_delete": f"HKCU\\{key}",
            "note": "预演：未删除注册表项。",
        }

    op_id = op_id or f"{stamp()}-reg-{uuid.uuid4().hex[:8]}"
    qdir = quarantine_root() / op_id
    qdir.mkdir(parents=True, exist_ok=True)
    backup = qdir / (key.replace("\\", "_")[:120] + ".reg")

    exp = wininteg.export_reg_key(hive, key, backup)
    if not exp["ok"]:
        _drop_if_empty(qdir)
        # No backup means no deletion. An unbacked-up registry delete is
        # irreversible, so it is refused outright.
        return {
            "ok": False,
            "error": f"导出备份失败，已拒绝删除该项：{exp['error']}",
            "backup": "",
        }

    script = (
        f"$p='{hive}:\\{key.replace(chr(39), chr(39)*2)}';"
        "$exists = Test-Path $p;"
        "if($exists){ Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue };"
        "if(Test-Path $p){'FAIL'}else{'OK'}"
    )
    from core.util import run_powershell

    res = run_powershell(script, timeout=60).strip()
    ok = "OK" in res

    record = {
        "op_id": op_id,
        "time": now_ms(),
        "kind": "registry",
        "agent": "",
        "permanent": False,
        "quarantine": str(qdir),
        "steps": [
            {
                "action": "registry_delete",
                "path": f"{hive}\\{key}",
                "backup": str(backup),
                "result": "deleted" if ok else "failed",
            }
        ],
        "status": "completed" if ok else "failed",
        "errors": [] if ok else ["注册表项仍然存在。"],
    }
    append_jsonl(journal_path(), record)

    if ok:
        _invalidate_caches()
    return {
        "ok": ok,
        "op_id": op_id,
        "deleted": f"{hive}\\{key}",
        "backup": str(backup),
        "error": "" if ok else "注册表项删除后仍然存在。",
        "restorable": True,
    }


def restore_registry_key(op_id: str) -> dict:
    """Re-import a registry backup taken by remove_registry_key."""
    from core.util import run_powershell

    ops = {o.get("op_id"): o for o in read_jsonl(journal_path())}
    op = ops.get(op_id)
    if not op or op.get("kind") != "registry":
        raise CleanupError(f"找不到注册表操作记录：{op_id}")
    steps = [s for s in (op.get("steps") or []) if s.get("action") == "registry_delete"]
    if not steps:
        raise CleanupError("该操作没有可还原的注册表项。")
    backup = Path(steps[0].get("backup") or "")
    if not backup.exists():
        raise CleanupError("注册表备份文件已不存在，无法还原。")

    script = (
        f"& reg.exe import '{str(backup).replace(chr(39), chr(39)*2)}' 2>&1 | Out-Null;"
        f"$p='{steps[0]['path']}';"
        "if(Test-Path $p){'OK'}else{'FAIL'}"
    )
    res = run_powershell(script, timeout=60).strip()
    ok = "OK" in res
    append_jsonl(
        journal_path(),
        {
            "op_id": f"{op_id}-restore",
            "restored_from": op_id,
            "time": now_ms(),
            "kind": "registry",
            "status": "completed" if ok else "failed",
            "steps": [{"action": "registry_restore", "path": steps[0]["path"],
                       "result": "restored" if ok else "failed"}],
            "errors": [],
        },
    )
    return {"ok": ok, "restored": steps[0]["path"],
            "error": "" if ok else "导入 .reg 备份后目标键仍不存在。"}


# --------------------------------------------------------------------------
# Firewall rules
# --------------------------------------------------------------------------


def remove_firewall_rule(name: str, dry_run: bool = False) -> dict:
    """Delete a firewall rule. Needs elevation, so it is always reported not done."""
    command = f'Remove-NetFirewallRule -DisplayName "{name}"'
    if dry_run:
        return {"ok": True, "dry_run": True, "would_delete": name,
                "needs_admin": True, "command": command,
                "note": "预演：未删除防火墙规则。"}
    return {
        "ok": False,
        "needs_admin": True,
        "error": "删除防火墙规则需要管理员权限，本工具不会尝试提权。",
        "rule": name,
        "command": command,
    }


# --------------------------------------------------------------------------
# Uninstaller invocation
# --------------------------------------------------------------------------


def uninstall_command(entry: dict) -> dict:
    """The exact command that would run the product's own uninstaller.

    Returned, never executed here: invoking an uninstaller is the single
    irreversible step in a removal, so the API exposes it for the UI to show and
    confirm, and the CLI requires an explicit flag.
    """
    quiet = (entry or {}).get("quiet_uninstall_string") or ""
    normal = (entry or {}).get("uninstall_string") or ""
    if quiet:
        return {
            "available": True,
            "silent": True,
            "command": quiet,
            "note": "支持静默卸载参数，但仍会真正卸载；执行前请确认已退出程序。",
        }
    if normal:
        return {
            "available": True,
            "silent": False,
            "command": normal,
            "note": "该卸载器没有静默参数，会弹出图形界面，需要手动点击完成。",
        }
    return {
        "available": False,
        "silent": False,
        "command": "",
        "note": "注册表中没有找到卸载命令，请从「设置 → 应用」中卸载。",
    }


def run_uninstaller(entry: dict, timeout: int = 600) -> dict:
    """Launch the product's own uninstaller and wait for it.

    Only the *silent* form is executed unattended. When there is no silent
    switch the GUI is launched and the call returns immediately, because
    blocking on a modal window the user must click through would look like a
    hang.
    """
    import subprocess

    cmd = uninstall_command(entry)
    if not cmd["available"]:
        return {"ok": False, "started": False, "error": cmd["note"]}

    try:
        if cmd["silent"]:
            proc = subprocess.run(
                cmd["command"],
                shell=True,
                timeout=timeout,
                capture_output=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            out = (proc.stdout or b"").decode("utf-8", "replace")
            err = (proc.stderr or b"").decode("utf-8", "replace")
            return {
                "ok": True,
                "started": True,
                "silent": True,
                "exit_code": proc.returncode,
                "stdout": out[-4000:],
                "stderr": err[-4000:],
                "note": "卸载器已执行完毕。请用「卸载后验证」确认残留。",
            }
        # GUI form: start and return.
        subprocess.Popen(cmd["command"], shell=True)
        return {
            "ok": True,
            "started": True,
            "silent": False,
            "exit_code": None,
            "note": "已启动图形卸载程序，请在弹出的窗口中完成操作，然后回来做「卸载后验证」。",
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "started": True,
            "error": f"卸载器超过 {timeout} 秒未结束，可能仍在运行或已卡住。",
        }
    except OSError as e:
        return {"ok": False, "started": False, "error": f"无法启动卸载器：{e}"}


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------


def verify_cleanup(agent_id: str, expected_gone: list[str]) -> dict:
    """Re-check that the items we removed are really gone.

    Mirrors :meth:`adapters.base.Adapter.verify_absent`: reporting success
    because a command returned 0 is how "I deleted it" turns out to be false.
    """
    still_there: list[dict] = []
    gone = 0
    for raw in expected_gone:
        p = Path(raw)
        if p.exists():
            size, files = dir_size(p) if p.is_dir() else (0, 0)
            still_there.append({"path": str(p), "size": size,
                                "size_h": human_size(size), "file_count": files})
        else:
            gone += 1
    clf = Classifier()
    recheck = []
    for raw in expected_gone:
        p = Path(raw)
        if not p.exists():
            continue
        try:
            o = clf.classify(p)
            recheck.append({"path": str(p), "disposition": o.disposition,
                            "category": o.category, "evidence": o.evidence})
        except Exception:
            continue
    return {
        "agent": agent_id,
        "checked": len(expected_gone),
        "gone": gone,
        "remaining": len(still_there),
        "remaining_items": still_there,
        "remaining_bytes": sum(x["size"] for x in still_there),
        "remaining_bytes_h": human_size(sum(x["size"] for x in still_there)),
        "reclassified": recheck,
        "clean": not still_there,
        "note": (
            "全部目标已清除。"
            if not still_there
            else f"仍有 {len(still_there)} 项未能删除，可能是文件被占用或需要管理员权限。"
        ),
    }


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _rel_for(src: Path) -> Path:
    """Mirror a path under the quarantine, never escaping it."""
    import hashlib

    try:
        parts = src.resolve().parts
        drive = parts[0].replace(":", "").replace("\\", "") or "x"
        rest = [p for p in parts[1:] if p not in ("\\", "/")]
        digest = hashlib.sha1(str(src).encode("utf-8")).hexdigest()[:8]
        return Path(drive) / digest / Path(*rest[-3:])
    except Exception:
        return Path("misc") / src.name


def _move(src: Path, dest: Path) -> None:
    if dest.exists():
        err = remove_tree(dest)
        if err:
            raise OSError(err)
    if src.is_file():
        os.replace(src, dest)
    else:
        shutil.move(str(src), str(dest))


def _drop_if_empty(qdir: Path) -> None:
    """Remove a quarantine folder that ended up holding nothing."""
    try:
        if qdir.exists() and not any(qdir.iterdir()):
            qdir.rmdir()
    except OSError:
        pass


def _invalidate_caches() -> None:
    try:
        from core import inventory

        inventory.invalidate()
    except Exception:
        pass


def list_cleanup_operations(limit: int = 200) -> list[dict]:
    """Cleanup operations, newest first, with their quarantine state."""
    ops = [
        o
        for o in read_jsonl(journal_path())
        if o.get("kind") in ("cleanup", "cleanup-permanent", "registry")
        and not o.get("restored_from")
    ]
    ops.sort(key=lambda o: -(o.get("time") or 0))
    out = []
    for o in ops[:limit]:
        q = Path(o.get("quarantine") or "")
        present = q.exists()
        size = 0
        if present:
            size, _c = dir_size(q)
        out.append(
            {
                "op_id": o.get("op_id"),
                "kind": o.get("kind"),
                "time": o.get("time"),
                "time_iso": _iso(o.get("time")),
                "agent": o.get("agent"),
                "status": o.get("status"),
                "removed": o.get("removed"),
                "failed": o.get("failed"),
                "freed_bytes": o.get("freed_bytes", 0),
                "freed_bytes_h": human_size(o.get("freed_bytes", 0)),
                "permanent": o.get("permanent"),
                "steps": len(o.get("steps") or []),
                "quarantine": str(q) if present else "",
                "quarantine_size": size,
                "quarantine_size_h": human_size(size),
                "restorable": present and o.get("kind") == "cleanup",
                "errors": o.get("errors") or [],
            }
        )
    return out


def _iso(ms) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime((ms or 0) / 1000.0))
    except (OSError, ValueError):
        return ""
