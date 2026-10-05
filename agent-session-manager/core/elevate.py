"""Privileged actions: do the few things that genuinely need Administrator.

Some residue cannot be removed by a normal user, and pretending otherwise is
worse than saying so:

  * ``HKLM`` registry keys              (machine-wide)
  * Windows Firewall rules              (machine-wide)
  * shortcuts under ``C:\\ProgramData`` (machine-wide Start Menu)

The tool used to stop at *reporting* these with a copy-paste command. That is
honest but incomplete, so this module adds the missing half: it collects the
privileged items into one batch, shows the user exactly what will run, and -- on
an explicit confirmation -- launches **one** elevated PowerShell that performs
them, then reads back a per-item result.

Design rules, in order of importance:

1. **Elevation is never silent.** The UAC prompt is the consent, and it is only
   ever raised by a direct user action carrying ``confirm``. Nothing here runs
   on a timer, on startup, or as a side effect of another call.
2. **The script is generated from validated inventory, never from free text.**
   Every target must already appear in :func:`privileged_actions` for that
   agent, so a caller cannot smuggle in an arbitrary registry path.
3. **Back up before deleting, or do not delete.** Registry keys are exported
   with ``reg export`` and firewall rules are dumped to JSON *inside the
   elevated script*, into the tool's own quarantine. A failed backup aborts
   that item rather than proceeding unprotected.
4. **Re-verify inside the elevated process.** Between the plan and the UAC
   prompt a target could change; each action re-checks its target first.
5. **Report per item.** One failure must not hide the rest, and a cancelled UAC
   prompt is reported as cancellation, not as success.
"""

from __future__ import annotations

import json
import re
import subprocess
import time
import uuid
from pathlib import Path

from core.util import data_root, human_size, now_ms, powershell_exe, quarantine_root

#: Action kinds this module knows how to perform.
KIND_FIREWALL = "firewall"
KIND_REGISTRY = "registry_key"
KIND_SHORTCUT = "shortcut"

KNOWN_KINDS = (KIND_FIREWALL, KIND_REGISTRY, KIND_SHORTCUT)

#: Windows' own codes for "the user declined the UAC prompt".
UAC_CANCELLED_CODES = (1223, -1073741510)
UAC_CANCELLED_HINTS = (
    "canceled by the user", "cancelled by the user",
    "操作已被用户取消", "用户取消",
)


def elevated_dir() -> Path:
    p = data_root() / "elevated"
    p.mkdir(parents=True, exist_ok=True)
    return p


# --------------------------------------------------------------------------
# 1. Collect the privileged items for one agent
# --------------------------------------------------------------------------


def privileged_actions(agent_id: str) -> dict:
    """Everything that needs Administrator, with a reason and a command.

    Read-only. Returns ``{"actions": [...], "count": n, "needs_elevation": bool}``
    where each action is a dict the script builder understands.
    """
    from core import residue as residue_mod

    plan = residue_mod.scan_agent(agent_id)
    win = plan.get("windows") or {}
    actions: list[dict] = []

    for r in win.get("firewall") or []:
        actions.append(
            {
                "kind": KIND_FIREWALL,
                "target": r.get("name", ""),
                "label": f"防火墙规则 {r.get('name','')}",
                "reason": f"入站/出站规则（{r.get('direction','')}），删除需要管理员权限",
            }
        )

    for k in win.get("blocked_registry_keys") or []:
        actions.append(
            {
                "kind": KIND_REGISTRY,
                "hive": k.get("hive", ""),
                "key": k.get("reg_key", ""),
                "target": f"{k.get('hive','')}\\{k.get('reg_key','')}",
                "label": f"注册表键 {k.get('hive','')}\\{k.get('reg_key','')}",
                "reason": "机器级注册表键（HKLM），删除需要管理员权限",
            }
        )

    for s in win.get("shortcuts") or []:
        if s.get("needs_admin") and s.get("path"):
            actions.append(
                {
                    "kind": KIND_SHORTCUT,
                    "target": s.get("path", ""),
                    "label": f"快捷方式 {Path(s.get('path','')).name}",
                    "reason": "位于 ProgramData/公共桌面，删除需要管理员权限",
                    "orphan": bool(s.get("orphan")),
                }
            )

    # De-duplicate by (kind, target): the same firewall rule or key can be
    # reported twice when an agent has several storage roots.
    seen: set[tuple[str, str]] = set()
    uniq: list[dict] = []
    for a in actions:
        k = (a["kind"], a.get("target", ""))
        if k in seen:
            continue
        seen.add(k)
        uniq.append(a)

    return {
        "agent": agent_id,
        "actions": uniq,
        "count": len(uniq),
        "needs_elevation": bool(uniq),
        "already_elevated": is_elevated(),
    }


# --------------------------------------------------------------------------
# 2. Elevation state and launching
# --------------------------------------------------------------------------


def is_elevated() -> bool:
    from core.wininteg import is_elevated as _f

    try:
        return bool(_f())
    except Exception:
        return False


def _ps_literal(value) -> str:
    """A PowerShell single-quoted literal.

    Inside single quotes PowerShell treats everything literally except `'`
    itself, which is escaped by doubling. That makes this sufficient for any
    path or registry key, including one containing `$`, a backtick or quotes.
    """
    return "'" + str(value).replace("'", "''") + "'"


def _comment_safe(value, limit: int = 140) -> str:
    """Make a value safe to place inside a PowerShell line comment.

    A line comment ends at the newline, so interpolating a raw name into
    `# --- firewall: <name>` lets a name containing a newline continue as real
    code -- and this script runs elevated. Windows permits newlines in NTFS
    filenames and firewall rule names are arbitrary strings, so that is a real
    path to arbitrary code execution as Administrator, not a theoretical one.

    Comments are for humans only, so anything that could end the line or alter
    parsing is flattened rather than escaped.
    """
    s = str(value)
    # Every character that can end a line, including the Unicode line separators
    # PowerShell also honours.
    s = re.sub(r"[\r\n\u0085\u2028\u2029]+", " ", s)
    # Drop remaining control characters, which only make the log unreadable.
    s = "".join(ch if ch >= " " else " " for ch in s)
    return s[:limit]


def _unsafe_reason(value) -> str:
    """Why this target must not be acted on, or ''.

    A line break or NUL in a firewall rule name, registry key or shortcut path
    is pathological: no legitimate installer produces one. Rather than quoting
    it faithfully -- which forces a multi-line literal into the script and makes
    the generated code hard to review -- the action is refused. Fail closed.
    """
    s = str(value)
    if any(ch in s for ch in "\r\n\u0085\u2028\u2029"):
        return "目标名称含换行符，已拒绝（可能是恶意构造，正常程序不会这样命名）"
    if "\x00" in s:
        return "目标名称含 NUL 字符，已拒绝"
    return ""


def build_script(actions: list[dict], result_path: Path, backup_dir: Path) -> str:
    """Generate the elevated script. Pure function, so it can be tested.

    Only kinds in :data:`KNOWN_KINDS` are emitted; an unknown kind is skipped
    rather than guessed at. Every action re-checks its target, backs it up, then
    removes it, and finally records a JSON result line.
    """
    lines: list[str] = [
        "$ErrorActionPreference='Continue'",
        "$ProgressPreference='SilentlyContinue'",
        f"$backup={_ps_literal(backup_dir)}",
        "New-Item -ItemType Directory -Force -Path $backup | Out-Null",
        "$results=New-Object System.Collections.ArrayList",
        "function Add-Result([string]$kind,[string]$target,[bool]$ok,[string]$err){",
        "  [void]$results.Add([pscustomobject]@{kind=$kind;target=$target;ok=$ok;error=$err})",
        "}",
        "function Add-Note([string]$kind,[string]$target,[string]$note){",
        "  [void]$results.Add([pscustomobject]@{kind=$kind;target=$target;ok=$true;error='';note=$note})",
        "}",
        "",
    ]

    for i, a in enumerate(actions):
        kind = a.get("kind")
        if kind not in KNOWN_KINDS:
            continue
        tag = f"{i:03d}"

        # Refuse pathological targets before emitting anything. Checking here
        # (rather than escaping and continuing) keeps every generated statement
        # on one line, so the script stays reviewable by eye.
        unsafe = _unsafe_reason(a.get("target", ""))
        if not unsafe and kind == KIND_REGISTRY:
            unsafe = _unsafe_reason(a.get("key", ""))
        if unsafe:
            lines += [
                f"# --- {tag} {_comment_safe(kind)}: refused",
                f"Add-Result {_ps_literal(kind)} {_ps_literal(_comment_safe(a.get('target','')))} "
                f"$false {_ps_literal(unsafe)}",
                "",
            ]
            continue

        if kind == KIND_FIREWALL:
            name = a.get("target", "")
            bak = str(backup_dir / f"firewall-{tag}.json")
            lines += [
                f"# --- {tag} firewall: {_comment_safe(name)}",
                f"$t={_ps_literal(name)}",
                "$rule=Get-NetFirewallRule -DisplayName $t -ErrorAction SilentlyContinue",
                "if(-not $rule){ Add-Note 'firewall' $t 'already absent' }",
                "else {",
                "  try {",
                f"    $rule | Select-Object * -ExcludeProperty CimClass,CimInstanceProperties,"
                f"CimSystemProperties,PSComputerName | ConvertTo-Json -Depth 3 |"
                f" Set-Content -Path {_ps_literal(bak)} -Encoding UTF8",
                "  } catch { }",
                f"  if(-not (Test-Path {_ps_literal(bak)})){{",
                "    Add-Result 'firewall' $t $false 'backup failed; not removed'",
                "  } else {",
                "    try {",
                "      $rule | Remove-NetFirewallRule -ErrorAction Stop",
                "      if(Get-NetFirewallRule -DisplayName $t -ErrorAction SilentlyContinue){",
                "        Add-Result 'firewall' $t $false 'still present after removal'",
                "      } else { Add-Result 'firewall' $t $true '' }",
                "    } catch { Add-Result 'firewall' $t $false $_.Exception.Message }",
                "  }",
                "}",
                "",
            ]

        elif kind == KIND_REGISTRY:
            hive = a.get("hive", "")
            key = a.get("key", "")
            hive_ps = "HKEY_LOCAL_MACHINE" if hive.upper().startswith("HKLM") else "HKEY_CURRENT_USER"
            full_ps = f"{hive_ps}\\{key}"
            bak = str(backup_dir / f"registry-{tag}.reg")
            lines += [
                f"# --- {tag} registry: {_comment_safe(hive + chr(92) + key)}",
                f"$p={_ps_literal('HKLM:\\' + key if hive_ps.endswith('MACHINE') else 'HKCU:\\' + key)}",
                f"$full={_ps_literal(full_ps)}",
                f"if(-not (Test-Path $p)){{ Add-Note 'registry_key' $full 'already absent' }}",
                "else {",
                f"  & reg.exe export $full {_ps_literal(bak)} /y 2>&1 | Out-Null",
                f"  if(-not (Test-Path {_ps_literal(bak)})){{",
                "    Add-Result 'registry_key' $full $false 'backup failed; not removed'",
                "  } else {",
                "    try {",
                "      Remove-Item -Path $p -Recurse -Force -ErrorAction Stop",
                "      if(Test-Path $p){ Add-Result 'registry_key' $full $false 'still present after removal' }",
                "      else { Add-Result 'registry_key' $full $true '' }",
                "    } catch { Add-Result 'registry_key' $full $false $_.Exception.Message }",
                "  }",
                "}",
                "",
            ]

        elif kind == KIND_SHORTCUT:
            path = a.get("target", "")
            safe = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(path).name)[:60]
            bak = str(backup_dir / f"shortcut-{tag}-{safe}")
            lines += [
                f"# --- {tag} shortcut: {_comment_safe(path)}",
                f"$t={_ps_literal(path)}",
                f"if(-not (Test-Path -LiteralPath $t)){{ Add-Note 'shortcut' $t 'already absent' }}",
                "else {",
                "  try {",
                f"    Copy-Item -LiteralPath $t -Destination {_ps_literal(bak)} -Force -ErrorAction Stop",
                "  } catch { }",
                f"  if(-not (Test-Path -LiteralPath {_ps_literal(bak)})){{",
                "    Add-Result 'shortcut' $t $false 'backup failed; not removed'",
                "  } else {",
                "    try {",
                "      Remove-Item -LiteralPath $t -Force -ErrorAction Stop",
                "      if(Test-Path -LiteralPath $t){ Add-Result 'shortcut' $t $false 'still present after removal' }",
                "      else { Add-Result 'shortcut' $t $true '' }",
                "    } catch { Add-Result 'shortcut' $t $false $_.Exception.Message }",
                "  }",
                "}",
                "",
            ]

    lines += [
        f"$results | ConvertTo-Json -Compress | Set-Content -Path {_ps_literal(result_path)} -Encoding UTF8",
        "'DONE'",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------
# 3. Run it
# --------------------------------------------------------------------------


def run_elevated(script: str, timeout: int = 900) -> dict:
    """Launch `script` in one elevated PowerShell and collect the results.

    Returns ``{"ok", "elevated", "cancelled", "exit_code", "results", "error"}``.
    A declined UAC prompt is reported as ``cancelled`` with ``ok=False`` -- it is
    never folded into success.
    """
    exe = powershell_exe()
    if not exe:
        return {"ok": False, "elevated": False, "cancelled": False,
                "exit_code": None, "results": [],
                "error": "找不到 PowerShell，无法提权执行。"}

    op_id = f"{time.strftime('%Y%m%d-%H%M%S')}-elev-{uuid.uuid4().hex[:8]}"
    base = elevated_dir() / op_id
    base.mkdir(parents=True, exist_ok=True)
    script_path = base / "run.ps1"
    result_path = base / "result.json"
    backup_dir = quarantine_root() / op_id / "_elevated-backup"

    # Written as explicit bytes with a UTF-8 BOM.
    #
    # Two Windows traps are avoided at once:
    #   * PowerShell 5.1 decodes a .ps1 using the ANSI code page unless a BOM
    #     says otherwise, so a plain UTF-8 write mangles any non-ASCII target --
    #     a Chinese shortcut name would be read as mojibake and the script would
    #     fail to parse or act on the wrong path. PowerShell 7 also honours the
    #     BOM, so one encoding serves both.
    #   * Text-mode writes translate every "\n" to "\r\n", which would silently
    #     alter a target that legitimately contains a newline (and change the
    #     script's hash). Bytes keep the file identical to `script`.
    script_path.write_bytes(b"\xef\xbb\xbf" + script.encode("utf-8"))

    # One outer PowerShell raises the UAC prompt and waits. `-PassThru` gives us
    # the child's exit code so a failure inside the elevated process is visible.
    outer = (
        "$ErrorActionPreference='Stop';"
        "try {"
        f"  $p = Start-Process -FilePath {_ps_literal(exe)} -Verb RunAs -Wait -PassThru "
        f"-ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',"
        f"{_ps_literal(str(script_path))};"
        "  Write-Output ('EXIT=' + $p.ExitCode)"
        "} catch { Write-Output ('ERR=' + $_.Exception.Message) }"
    )

    try:
        proc = subprocess.run(
            [exe, "-NoProfile", "-NonInteractive", "-Command", outer],
            capture_output=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        raw = ((proc.stdout or b"") + (proc.stderr or b"")).decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return {"ok": False, "elevated": False, "cancelled": False,
                "exit_code": None, "results": [], "op_id": op_id,
                "error": f"提权操作超过 {timeout} 秒未结束（UAC 窗口可能仍在等待确认）。"}
    except OSError as e:
        return {"ok": False, "elevated": False, "cancelled": False,
                "exit_code": None, "results": [], "op_id": op_id,
                "error": f"无法启动提权进程：{e}"}

    low = raw.lower()
    cancelled = any(str(c) in raw for c in UAC_CANCELLED_CODES) or any(
        h in low for h in UAC_CANCELLED_HINTS
    )
    exit_code = None
    m = re.search(r"EXIT=(-?\d+)", raw)
    if m:
        exit_code = int(m.group(1))

    results: list[dict] = []
    if result_path.exists():
        try:
            data = json.loads(result_path.read_text(encoding="utf-8") or "[]")
            results = data if isinstance(data, list) else [data]
        except ValueError:
            results = []

    if cancelled:
        return {"ok": False, "elevated": False, "cancelled": True,
                "exit_code": exit_code, "results": results, "op_id": op_id,
                "error": "你取消了管理员授权（UAC），未做任何修改。"}

    if not results and "ERR=" in raw:
        return {"ok": False, "elevated": False, "cancelled": False,
                "exit_code": exit_code, "results": [], "op_id": op_id,
                "error": "提权启动失败：" + raw.split("ERR=", 1)[1].strip()[:200]}

    ok = bool(results) and all(r.get("ok") for r in results)
    return {
        "ok": ok,
        "elevated": True,
        "cancelled": False,
        "exit_code": exit_code,
        "results": results,
        "op_id": op_id,
        "script": str(script_path),
        "result_file": str(result_path),
        "backup_dir": str(backup_dir),
        "error": "" if ok else "部分项目未能完成，见 results。",
    }


# --------------------------------------------------------------------------
# 4. The user-facing entry point
# --------------------------------------------------------------------------


def plan(agent_id: str) -> dict:
    """What would run, and the exact script text. Read-only, safe to show."""
    items = privileged_actions(agent_id)
    actions = items["actions"]
    result_path = elevated_dir() / "preview-result.json"
    backup_dir = quarantine_root() / "preview" / "_elevated-backup"
    script = build_script(actions, result_path, backup_dir) if actions else ""
    return {
        **items,
        "script": script,
        "note": (
            f"共 {len(actions)} 项需要管理员权限，将合并为一次 UAC 授权执行。"
            "每项在删除前都会先导出备份到隔离区，失败会逐项报告。"
            if actions else "本机没有需要管理员权限的残留项。"
        ),
    }


def execute(agent_id: str, confirm: bool = False,
            only: list[str] | None = None) -> dict:
    """Run the privileged actions after an explicit confirmation.

    `only` restricts to specific targets (so the UI can let a user pick), but
    every entry is still checked against the freshly computed inventory: the
    caller may narrow the set, never widen it.
    """
    if not confirm:
        return {"ok": False, "cancelled": False, "elevated": False,
                "results": [], "error": "必须显式确认：提权删除不可撤销，请传入 confirm。"}

    if is_elevated():
        # Already Administrator: run in-process through the normal, journaled
        # path instead of raising a pointless UAC prompt.
        return {"ok": True, "already_elevated": True, "results": [],
                "note": "当前已是管理员权限，无需提权；请直接使用普通清理。"}

    items = privileged_actions(agent_id)
    actions = items["actions"]
    if only:
        wanted = set(only)
        allowed = {a.get("target") for a in actions}
        actions = [a for a in actions if a.get("target") in wanted]
        rejected = wanted - allowed
        if rejected:
            return {"ok": False, "cancelled": False, "elevated": False, "results": [],
                    "error": "以下目标不在该 Agent 的可提权清单中，已拒绝："
                             + "、".join(sorted(rejected))}
    if not actions:
        return {"ok": True, "elevated": False, "cancelled": False, "results": [],
                "note": "没有需要管理员权限的项目。"}

    op_id = f"{time.strftime('%Y%m%d-%H%M%S')}-elev-{uuid.uuid4().hex[:8]}"
    base = elevated_dir() / op_id
    base.mkdir(parents=True, exist_ok=True)
    result_path = base / "result.json"
    backup_dir = quarantine_root() / op_id / "_elevated-backup"
    script = build_script(actions, result_path, backup_dir)

    started = now_ms()
    out = run_elevated(script)
    out["agent"] = agent_id
    out["planned"] = len(actions)
    out["elapsed_ms"] = now_ms() - started

    # Journal it with the same discipline as every other destructive path, so
    # an elevated deletion is as auditable and reversible as a normal one.
    try:
        from core.util import append_jsonl, journal_path

        append_jsonl(journal_path(), {
            "op_id": out.get("op_id") or op_id,
            "time": now_ms(),
            "kind": "elevated",
            "agent": agent_id,
            "permanent": False,
            "quarantine": str(backup_dir.parent),
            "elevated": bool(out.get("elevated")),
            "cancelled": bool(out.get("cancelled")),
            "planned": len(actions),
            "steps": [
                {"action": r.get("kind"), "path": r.get("target"),
                 "result": "deleted" if r.get("ok") else "failed",
                 "error": r.get("error", "")}
                for r in out.get("results", [])
            ],
            "status": "completed" if out.get("ok") else (
                "cancelled" if out.get("cancelled") else "failed"),
            "errors": [out.get("error")] if out.get("error") else [],
        })
    except Exception:
        pass

    if out.get("ok"):
        try:
            from core import inventory

            inventory.invalidate()
        except Exception:
            pass
    return out


def restore_hint(op_id: str) -> dict:
    """Where the backups for an elevated run live, and whether they exist."""
    q = quarantine_root() / op_id / "_elevated-backup"
    if not q.exists():
        return {"op_id": op_id, "available": False, "path": "",
                "files": [], "note": "找不到该次提权操作的备份。"}
    files = [p.name for p in sorted(q.iterdir()) if p.is_file()]
    total = sum(p.stat().st_size for p in q.iterdir() if p.is_file())
    return {
        "op_id": op_id,
        "available": bool(files),
        "path": str(q),
        "files": files,
        "bytes": total,
        "bytes_h": human_size(total),
        "note": "注册表可用 reg import 还原，快捷方式可直接复制回去，防火墙规则见 JSON。",
    }
