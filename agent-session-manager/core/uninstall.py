"""Uninstall flow: retiring an agent completely, in five reviewable stages.

Stage 1  **preflight**   is it running? are sessions pinned? which uninstaller?
                         what will be left behind? What needs admin?
Stage 2  **uninstall**   run the product's own uninstaller (the only
                         irreversible step, always confirmed explicitly)
Stage 3  **verify**      re-scan: what survived the uninstaller?
Stage 4  **cleanup**     remove the residue, by disposition, reversibly
Stage 5  **report**      what was removed, what remains, what needs admin,
                         and a rollback id for each reversible operation

The design rule throughout: this module never decides on its own to remove
anything. It computes options, and the caller (UI or CLI) confirms. Stage 2 in
particular is never automatic.

Why not just "delete the folder"? Because a product installs itself in a dozen
places -- an Electron profile here, a WebView2 data dir there, a firewall rule,
an autostart entry, a vendor registry key -- and deleting only the folder the
adapter knows about is exactly the incomplete cleanup users complain about.
"""

from __future__ import annotations

from pathlib import Path

from core import cleaner
from core.ownership import NEVER, REVIEW, SAFE
from core.residue import ResidueScanner
from core.util import human_size


def preflight(agent_id: str) -> dict:
    """Everything a user must know before starting.

    Read-only. Safe to run while the agent is running (it will say so).
    """
    from adapters.registry import get_adapter

    adapter = get_adapter(agent_id)
    label = getattr(adapter, "label", "") or agent_id

    blockers = cleaner.protection(agent_id, adapter)["blockers"]

    residue = ResidueScanner(agent_id, adapter).scan(include_windows=True)
    win = residue.get("windows") or {}
    entry = win.get("uninstall")
    cmd = cleaner.uninstall_command(entry or {})

    # Sessions are listed so the user sees what conversation history goes away.
    sessions: list[dict] = []
    try:
        from core import inventory

        for s in inventory.scan():
            if s.agent != agent_id:
                continue
            sessions.append(
                {
                    "sid": s.sid,
                    "title": s.title,
                    "size": s.size,
                    "size_h": human_size(s.size),
                    "updated_at": s.updated_at,
                    "pinned": False,
                }
            )
    except Exception:
        pass
    try:
        from core import store

        store.decorate(sessions)
    except Exception:
        pass

    pinned = [s for s in sessions if s.get("pinned") or s.get("protected")]
    if pinned:
        blockers.append(
            {
                "kind": "session_pin",
                "title": f"{len(pinned)} 个会话被标记为「保留」",
                "detail": "卸载会删除这些会话的内容。",
                "action": "如仍需卸载，请先导出这些会话或取消保留标记。",
                "items": [s.get("sid", "") for s in pinned[:30]],
            }
        )

    summary = residue.get("summary") or {}
    env = residue.get("environment") or {}

    return {
        "agent": agent_id,
        "label": label,
        "installed": bool(residue.get("installed")),
        "blockers": blockers,
        "can_proceed": not [b for b in blockers if b["kind"] == "process"],
        "uninstall": {
            **cmd,
            "registry_name": (entry or {}).get("name", ""),
            "version": (entry or {}).get("version", ""),
            "publisher": (entry or {}).get("publisher", ""),
            "install_location": (entry or {}).get("install_location", ""),
            "registry_key": (
                f"{(entry or {}).get('reg_hive', '')}\\{(entry or {}).get('reg_key', '')}"
                if entry
                else ""
            ),
            "found": entry is not None,
        },
        "residue": {
            "summary": summary,
            "roots": [r for r in (residue.get("files") or [])
                      if r.get("confidence") == "exact"],
        },
        "sessions": {
            "count": len(sessions),
            "pinned": len(pinned),
            "items": sessions[:200],
        },
        "windows": {
            "registry_keys": win.get("registry_keys") or [],
            "removable_registry_keys": win.get("removable_registry_keys") or [],
            "blocked_registry_keys": win.get("blocked_registry_keys") or [],
            "firewall": win.get("firewall") or [],
            "shortcuts": win.get("shortcuts") or [],
            "services": win.get("services") or [],
            "scheduled_tasks": win.get("scheduled_tasks") or [],
            "autostart": win.get("autostart") or [],
            "needs_admin": win.get("needs_admin", False),
        },
        "credentials": residue.get("credentials") or [],
        "temp": residue.get("temp") or [],
        "environment": env,
        "elevated": bool(env.get("elevated")),
        "stages": [
            {"id": "preflight", "label": "预检", "done": True},
            {"id": "uninstall", "label": "调用官方卸载器", "done": False},
            {"id": "verify", "label": "卸载后验证", "done": False},
            {"id": "cleanup", "label": "清理残留", "done": False},
            {"id": "report", "label": "生成报告", "done": False},
        ],
    }


def cleanup_plan(agent_id: str) -> dict:
    """Group the residue into what can be removed, by disposition.

    `safe` items are offered pre-checked; `review` items are offered but not
    checked; `never` items are listed with the reason they are refused, so the
    user can see what is deliberately being left alone rather than wondering
    whether the tool missed it.
    """
    from adapters.registry import get_adapter

    adapter = get_adapter(agent_id)
    residue = ResidueScanner(agent_id, adapter).scan(include_windows=True)

    safe: list[dict] = []
    review: list[dict] = []
    never: list[dict] = []

    def _bucket(items, default_disp=None):
        for it in items:
            d = dict(it)
            d.setdefault("disposition", default_disp or REVIEW)
            if d["disposition"] == SAFE:
                safe.append(d)
            elif d["disposition"] == NEVER:
                never.append(d)
            else:
                review.append(d)

    # Files/dirs: skip the adapter's own data roots here. Those are handled by
    # the "remove all data" option, which the user must opt into separately.
    for it in residue.get("files") or []:
        if it.get("confidence") == "exact" and _is_root(it["path"], adapter):
            d = dict(it)
            d["disposition"] = REVIEW
            d["evidence"] = (d.get("evidence", "")
                             + "；这是该 Agent 的数据根目录，需单独确认")
            d["is_data_root"] = True
            review.append(d)
            continue
        _bucket([it])

    _bucket(residue.get("temp") or [])
    _bucket(residue.get("credentials") or [])

    win = residue.get("windows") or {}
    for k in win.get("removable_registry_keys") or []:
        safe.append(
            {
                "path": f"{k['hive']}\\{k['reg_key']}",
                "kind": "registry",
                "hive": k["hive"],
                "reg_key": k["reg_key"],
                "disposition": REVIEW,
                "category": "config",
                "evidence": f"注册表项 “{k['name']}” 由该产品创建，卸载后通常残留",
                "size": 0,
                "size_h": "—",
            }
        )
    for k in win.get("blocked_registry_keys") or []:
        never.append(
            {
                "path": f"{k['hive']}\\{k['reg_key']}",
                "kind": "registry_blocked",
                "disposition": NEVER,
                "category": "shared",
                "evidence": f"共享注册表根 “{k['name']}”，其他软件也在使用，禁止删除",
                "size": 0,
                "size_h": "—",
            }
        )
    for r in win.get("firewall") or []:
        review.append(
            {
                "path": r["name"],
                "kind": "firewall",
                "disposition": REVIEW,
                "category": "config",
                "needs_admin": True,
                "evidence": f"防火墙规则 “{r['name']}”（{r['direction']}），删除需要管理员权限",
                "size": 0,
                "size_h": "—",
            }
        )
    for s in win.get("shortcuts") or []:
        review.append(
            {
                "path": s["path"],
                "kind": "shortcut",
                "disposition": SAFE if s.get("orphan") else REVIEW,
                "category": "config",
                "orphan": s.get("orphan", False),
                "needs_admin": s.get("needs_admin", False),
                "evidence": (
                    f"快捷方式指向的目标已不存在：{s.get('target', '')}"
                    if s.get("orphan")
                    else f"快捷方式仍指向存在的程序：{s.get('target', '')}"
                ),
                "size": 0,
                "size_h": "—",
            }
        )
    for s in (win.get("services") or []) + (win.get("scheduled_tasks") or []):
        never.append(
            {
                "path": s.get("display_name") or s.get("name", ""),
                "kind": "system",
                "disposition": NEVER,
                "category": "shared",
                "needs_admin": True,
                "evidence": "系统服务或计划任务，删除需要管理员权限，本工具只报告不执行",
                "size": 0,
                "size_h": "—",
            }
        )
    for a in win.get("autostart") or []:
        review.append(
            {
                "path": f"{a['key']}\\{a['name']}",
                "kind": "autostart",
                "disposition": REVIEW,
                "category": "config",
                "needs_admin": a.get("needs_admin", False),
                "evidence": f"开机自启项指向：{a.get('value', '')}",
                "size": 0,
                "size_h": "—",
            }
        )

    def _total(items):
        return sum(i.get("size") or 0 for i in items)

    return {
        "agent": agent_id,
        "label": getattr(adapter, "label", "") or agent_id,
        "safe": safe,
        "review": review,
        "never": never,
        "safe_bytes": _total(safe),
        "safe_bytes_h": human_size(_total(safe)),
        "review_bytes": _total(review),
        "review_bytes_h": human_size(_total(review)),
        "counts": {"safe": len(safe), "review": len(review), "never": len(never)},
        "note": (
            f"可安全清理 {len(safe)} 项（{human_size(_total(safe))}）；"
            f"需人工确认 {len(review)} 项；"
            f"禁止删除 {len(never)} 项（已列出原因）。"
        ),
    }


def _is_root(path: str, adapter) -> bool:
    if adapter is None:
        return False
    try:
        return cleaner.is_declared_root(Path(path), adapter)
    except Exception:
        return False


def verify(agent_id: str) -> dict:
    """Stage 3: what survived the uninstaller.

    Re-scans from scratch and compares against the preflight picture, so
    "the uninstaller said it succeeded" is checked rather than believed.
    """
    from adapters.registry import get_adapter

    adapter = get_adapter(agent_id)
    residue = ResidueScanner(agent_id, adapter).scan(include_windows=True)
    summary = residue.get("summary") or {}
    win = residue.get("windows") or {}

    still_installed = False
    try:
        still_installed = bool(adapter and adapter.detect())
    except Exception:
        still_installed = False

    remaining = [
        f for f in (residue.get("files") or [])
        if (f.get("size") or 0) > 0 and f.get("disposition") != NEVER
    ]
    remaining_bytes = sum(f.get("size") or 0 for f in remaining)

    return {
        "agent": agent_id,
        "still_installed": still_installed,
        "uninstall_entry_present": bool(win.get("uninstall")),
        "registry_entry": win.get("uninstall"),
        "reclaimable_bytes": summary.get("reclaimable_bytes", 0),
        "reclaimable_bytes_h": summary.get("reclaimable_bytes_h", "0 B"),
        "remaining_items": len(remaining),
        "remaining_bytes": remaining_bytes,
        "remaining_bytes_h": human_size(remaining_bytes),
        "directories_still_present": len(
            [r for r in (residue.get("files") or []) if r.get("confidence") == "exact"]
        ),
        "credentials_left": len(residue.get("credentials") or []),
        "needs_admin": summary.get("needs_admin", False),
        "note": (
            "卸载已生效，未检测到该 Agent 仍然安装。"
            if not still_installed and not win.get("uninstall")
            else "注册表或数据目录中仍能检测到该 Agent；若有残留可继续下一步清理。"
        ),
    }


def execute_cleanup(
    agent_id: str,
    paths: list[str] | None = None,
    dispositions: list[str] | None = None,
    include_data_roots: bool = False,
    permanent: bool = False,
    dry_run: bool = False,
    force_while_running: bool = False,
) -> dict:
    """Stage 4: remove the selected residue.

    `paths` selects specific items. When omitted, `dispositions` decides: the
    default is `["safe"]`, so an unqualified call removes only the items that
    are unambiguously disposable. `review` items require being named
    explicitly, which is the point of the three-tier model.
    """
    plan = cleanup_plan(agent_id)

    if paths is None:
        wanted = dispositions or [SAFE]
        chosen = []
        for d in wanted:
            if d == SAFE:
                chosen += plan["safe"]
            elif d == REVIEW:
                chosen += plan["review"]
        if include_data_roots:
            chosen += [i for i in plan["review"] if i.get("is_data_root")]
    else:
        by_path = {}
        for bucket in ("safe", "review", "never"):
            for i in plan[bucket]:
                by_path[i.get("path")] = (i, bucket)
        chosen = []
        refused = []
        for p in paths:
            hit = by_path.get(p)
            if hit is None:
                # Not in the plan: let the executor re-classify it rather than
                # silently dropping it, so the user gets a real reason.
                chosen.append({"path": p})
                continue
            item, bucket = hit
            if bucket == "never":
                refused.append({"path": p, "reason": item.get("evidence", "")})
                continue
            if item.get("is_data_root") and not include_data_roots:
                refused.append(
                    {"path": p, "reason": "这是该 Agent 的数据根目录，需显式确认后才可删除。"}
                )
                continue
            chosen.append(item)

    file_paths = [c["path"] for c in chosen
                  if c.get("kind") not in ("registry", "firewall", "shortcut",
                                           "autostart", "system", "registry_blocked")]
    registry_keys = [c for c in chosen if c.get("kind") == "registry"]
    firewall = [c for c in chosen if c.get("kind") == "firewall"]
    needs_admin = [c for c in chosen if c.get("needs_admin")]

    result: dict = {
        "ok": True,
        "agent": agent_id,
        "dry_run": bool(dry_run),
        "selected": len(chosen),
        "file_ops": None,
        "registry_ops": [],
        "firewall_ops": [],
        "needs_admin": [
            {"path": c.get("path"), "kind": c.get("kind"),
             "command": _admin_command(c)} for c in needs_admin
        ],
        "files": {"removed": 0, "failed": 0, "bytes": 0, "bytes_h": "0 B"},
    }

    if file_paths:
        r = cleaner.CleanupExecutor().execute(
            agent_id,
            file_paths,
            allow_permanent=permanent,
            dry_run=dry_run,
            force_while_running=force_while_running,
            allow_roots=include_data_roots,
        )
        result["file_ops"] = r
        if dry_run:
            # A preview must still tell the truth about the *scale* of what is
            # proposed, otherwise "0 removed" reads as "nothing to do".
            pfp = r.get("preflight") or {}
            result["files"] = {
                "removed": 0,
                "failed": pfp.get("refused", 0),
                "bytes": 0,
                "bytes_h": "0 B",
                "would_remove": pfp.get("will_remove", 0),
                "would_remove_bytes": pfp.get("will_remove_bytes", 0),
                "would_remove_bytes_h": pfp.get("will_remove_bytes_h", "0 B"),
            }
        else:
            result["files"] = {
                "removed": r.get("removed", 0),
                "failed": r.get("failed", 0),
                "bytes": r.get("bytes", 0),
                "bytes_h": r.get("bytes_h", "0 B"),
            }

    for k in registry_keys:
        result["registry_ops"].append(
            cleaner.remove_registry_key(k["hive"], k["reg_key"], dry_run=dry_run)
        )
    for f in firewall:
        result["firewall_ops"].append(
            cleaner.remove_firewall_rule(f["path"], dry_run=dry_run)
        )

    removed = result["files"]["removed"]
    failed = result["files"]["failed"]
    if dry_run:
        result["note"] = (
            f"预演：将移除 {result['files'].get('would_remove', 0)} 项"
            f"（{result['files'].get('would_remove_bytes_h', '0 B')}）"
            f"，拒绝 {failed} 项"
            + (f"；{len(result['needs_admin'])} 项需要管理员权限。"
               if result["needs_admin"] else "。")
            + " 未修改任何文件。"
        )
        return result
    result["note"] = (
        f"已移除 {removed} 项（{result['files']['bytes_h']}）"
        + (f"，{failed} 项失败" if failed else "")
        + (f"；{len(result['needs_admin'])} 项需要管理员权限，见 needs_admin。"
           if result["needs_admin"] else "。")
    )
    return result


def _admin_command(item: dict) -> str:
    kind = item.get("kind")
    p = item.get("path", "")
    if kind == "firewall":
        return f'Remove-NetFirewallRule -DisplayName "{p}"'
    if kind == "registry":
        return f'reg delete "{p}" /f'
    if kind == "system":
        return f'# 请手动停用并删除：{p}'
    if kind == "autostart":
        return f'reg delete "{p}" /f'
    if kind == "shortcut" and item.get("needs_admin"):
        return f'Remove-Item "{p}" -Force'
    return f'# 需要管理员权限：{p}'


def report(agent_id: str, op_ids: list[str] | None = None) -> dict:
    """Stage 5: a complete account of what happened."""
    verify_result = verify(agent_id)
    ops = cleaner.list_cleanup_operations()
    mine = [o for o in ops if o.get("agent") == agent_id]
    if op_ids:
        mine = [o for o in mine if o.get("op_id") in op_ids]
    total_freed = sum(o.get("freed_bytes") or 0 for o in mine)
    return {
        "agent": agent_id,
        "operations": mine,
        "operation_count": len(mine),
        "total_freed_bytes": total_freed,
        "total_freed_bytes_h": human_size(total_freed),
        "verify": verify_result,
        "restorable": [
            {"op_id": o["op_id"], "restorable": o["restorable"],
             "quarantine": o["quarantine"]}
            for o in mine if o.get("restorable")
        ],
        "note": (
            f"共 {len(mine)} 次清理操作，释放 {human_size(total_freed)}；"
            "可在「操作记录」中逐项还原（永久删除的除外）。"
        ),
    }


def full_report() -> dict:
    """Residue and install state for every agent, for the overview page."""
    from adapters.registry import all_adapters

    out = []
    for a in all_adapters():
        try:
            residue = ResidueScanner(a.id, a).scan(include_windows=False)
            s = residue.get("summary") or {}
            out.append(
                {
                    "agent": a.id,
                    "label": a.label,
                    "installed": bool(residue.get("installed")),
                    "reclaimable_bytes": s.get("reclaimable_bytes", 0),
                    "reclaimable_bytes_h": s.get("reclaimable_bytes_h", "0 B"),
                    "review_bytes": s.get("review_bytes", 0),
                    "review_bytes_h": s.get("review_bytes_h", "0 B"),
                    "never_bytes": s.get("never_bytes", 0),
                    "never_bytes_h": s.get("never_bytes_h", "0 B"),
                    "credentials": s.get("credential_count", 0),
                }
            )
        except Exception as e:
            out.append({"agent": a.id, "label": a.label, "installed": False,
                        "error": f"{type(e).__name__}: {e}"})
    out.sort(key=lambda x: -(x.get("reclaimable_bytes") or 0))
    return {
        "agents": out,
        "total_reclaimable": sum(a.get("reclaimable_bytes") or 0 for a in out),
        "total_reclaimable_h": human_size(
            sum(a.get("reclaimable_bytes") or 0 for a in out)
        ),
    }
