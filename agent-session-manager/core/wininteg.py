"""Windows integration inventory: everything an uninstall leaves behind that is
not a file in the user's profile.

A complete removal has to account for five more surfaces than a file tree:

  * **uninstall registry entries** -- where the official uninstaller lives, and
    what it claims the product is
  * **vendor registry keys** -- ``HKCU\\SOFTWARE\\<vendor>`` settings that
    outlive the program
  * **firewall rules** -- named rules the installer added
  * **Start Menu / Desktop shortcuts** -- whose targets may already be gone
  * **services, scheduled tasks, autostart entries** -- things that would
    otherwise try to run a program that no longer exists

Two rules shape this module:

  1. **Read-only.** It discovers and reports. Every mutation goes through the
     executor, which journals and can roll back.
  2. **Never guess about shared resources.** ``HKCU\\SOFTWARE\\Tencent`` is not
     WorkBuddy's key even though WorkBuddy is made by Tencent: QQ and WeChat
     store their settings there too. Anything under a shared vendor root is
     reported as shared and refused.

PowerShell is used because the standard library cannot read the registry. Every
call is bounded by a timeout and degrades to "unknown" rather than raising.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from core.util import (
    home,
    local_appdata,
    program_data,
    roaming_appdata,
    run_powershell,
)

# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

UNINSTALL_KEYS = (
    r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    r"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
)

#: Vendor roots that belong to more than one product. A key under one of these
#: is never attributed to a single agent.
SHARED_REGISTRY_ROOTS = {
    "tencent",   # QQ, WeChat, QQNT, QQProtect all live here
    "microsoft",
    "google",
    "mozilla",
    "apple",
    "adobe",
    "oracle",
    "intel",
    "nvidia",
    "realtek",
    "wow6432node",
    "windows",
    "policies",
    "classes",
}

#: Hives this process can write to without elevation.
WRITABLE_HIVES = ("HKCU:",)


def _ps_json(script: str, timeout: int = 60):
    """Run a PowerShell script that ends in ConvertTo-Json and parse it."""
    raw = run_powershell(script, timeout=timeout).strip()
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    if isinstance(data, dict):
        return [data]
    return data if isinstance(data, list) else None


def uninstall_entries() -> list[dict]:
    """Installed AI-agent products, with everything needed to remove them.

    Unlike the lighter probe in `adapters.registry`, this reads the uninstall
    strings, the install location, the publisher and the estimated size, and it
    keeps the registry key path so the entry itself can be removed afterwards.
    """
    quoted = ",".join("'" + p.replace("'", "''") + "'" for p in UNINSTALL_KEYS)
    script = (
        f"$paths=@({quoted});"
        "Get-ItemProperty $paths -ErrorAction SilentlyContinue | "
        "Where-Object {$_.DisplayName} | "
        "Select-Object DisplayName,DisplayVersion,Publisher,InstallLocation,"
        "UninstallString,QuietUninstallString,DisplayIcon,EstimatedSize,"
        "@{n='RegKey';e={$_.PSPath}} | ConvertTo-Json -Compress"
    )
    data = _ps_json(script, timeout=90) or []

    out: list[dict] = []
    for item in data:
        name = (item.get("DisplayName") or "").strip()
        if not name:
            continue
        reg = str(item.get("RegKey") or "")
        # PSPath looks like:
        #   Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\SOFTWARE\...
        hive, key = _split_pspath(reg)
        out.append(
            {
                "name": name,
                "version": (item.get("DisplayVersion") or "").strip(),
                "publisher": (item.get("Publisher") or "").strip(),
                "install_location": (item.get("InstallLocation") or "").strip(),
                "uninstall_string": (item.get("UninstallString") or "").strip(),
                "quiet_uninstall_string": (item.get("QuietUninstallString") or "").strip(),
                "display_icon": (item.get("DisplayIcon") or "").strip(),
                "estimated_size": _to_int(item.get("EstimatedSize")),
                "reg_hive": hive,
                "reg_key": key,
                "reg_writable": hive in ("HKCU",),
            }
        )
    out.sort(key=lambda x: x["name"].lower())
    return out


def _to_int(v) -> int:
    try:
        return int(v) * 1024 if v and int(v) < 100 * 1024 * 1024 else int(v or 0)
    except (TypeError, ValueError):
        return 0


def _split_pspath(pspath: str) -> tuple[str, str]:
    """``...Registry::HKEY_CURRENT_USER\\SOFTWARE\\X`` -> ("HKCU", "SOFTWARE\\X")."""
    s = pspath
    if "Registry::" in s:
        s = s.split("Registry::", 1)[1]
    s = s.replace("HKEY_CURRENT_USER", "HKCU").replace("HKEY_LOCAL_MACHINE", "HKLM")
    s = s.replace("HKEY_CLASSES_ROOT", "HKCR").replace("HKEY_USERS", "HKU")
    hive, _, rest = s.partition("\\")
    return hive.strip(), rest.strip()


def match_entry(entries: list[dict], label: str, aliases: list[str] | None = None) -> dict | None:
    """The registry entry that corresponds to an agent label.

    Matching is deliberately strict: an exact (case-insensitive) name match, or
    a match on a token of the label at a word boundary. Substring matching is
    NOT used -- "Code" would otherwise match half the machine.
    """
    want = [t for t in str(label).lower().split() if len(t) > 2]
    if aliases:
        want += [a.lower() for a in aliases if a]
    for e in entries:
        n = e["name"].lower()
        if n in want:
            return e
    for e in entries:
        n = e["name"].lower()
        for w in want:
            if re.search(r"(?<![a-z0-9])" + re.escape(w) + r"(?![a-z0-9])", n):
                return e
    return None


def vendor_keys() -> list[dict]:
    """``HKCU``/``HKLM`` vendor keys that look agent-related.

    Reports the key, its subkey count, and whether it is shared. Only HKCU keys
    are marked removable without elevation.
    """
    script = (
        "$roots=@('HKCU:\\SOFTWARE','HKLM:\\SOFTWARE');"
        "$out=@();"
        "foreach($r in $roots){"
        " Get-ChildItem $r -ErrorAction SilentlyContinue | ForEach-Object {"
        "  $sub=(Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | Measure-Object).Count;"
        "  $out += [pscustomobject]@{"
        "   Hive=($_.PSPath -replace '.*Registry::','' -replace '\\\\SOFTWARE.*','');"
        "   Name=$_.PSChildName; Path=$_.PSPath; SubKeys=$sub } } };"
        "$out | ConvertTo-Json -Compress"
    )
    data = _ps_json(script, timeout=90) or []
    out: list[dict] = []
    for item in data:
        name = str(item.get("Name") or "").strip()
        if not name:
            continue
        hive, key = _split_pspath(str(item.get("Path") or ""))
        out.append(
            {
                "name": name,
                "hive": hive,
                "reg_key": key,
                "subkeys": int(item.get("SubKeys") or 0),
                "shared": name.lower() in SHARED_REGISTRY_ROOTS,
                "removable": hive == "HKCU" and name.lower() not in SHARED_REGISTRY_ROOTS,
            }
        )
    out.sort(key=lambda x: (x["hive"], x["name"].lower()))
    return out


def export_reg_key(hive: str, key: str, dest) -> dict:
    """Export a key to a .reg file before deleting it, for rollback.

    Returns ``{"ok": bool, "path": str, "error": str}``. A key that cannot be
    exported must not be deleted -- an unbacked-up registry deletion is exactly
    the irreversible step this tool promises never to take.
    """
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    full = f"{hive}\\{key}"
    script = (
        f"$p='{full}';"
        f"$out='{str(dest).replace(chr(39), chr(39)*2)}';"
        "& reg.exe export $p $out /y 2>&1 | Out-Null;"
        "if (Test-Path $out) { 'OK' } else { 'FAIL' }"
    )
    res = run_powershell(script, timeout=60).strip()
    ok = "OK" in res
    return {
        "ok": ok,
        "path": str(dest),
        "error": "" if ok else f"导出失败或键不存在：{full}",
    }


# --------------------------------------------------------------------------
# Firewall rules
# --------------------------------------------------------------------------


def firewall_rules(names: list[str] | None = None) -> list[dict]:
    """Firewall rules whose display name matches any candidate token."""
    script = (
        "Get-NetFirewallRule -ErrorAction SilentlyContinue | "
        "Select-Object DisplayName,Direction,Action,Enabled,Profile | "
        "ConvertTo-Json -Compress"
    )
    data = _ps_json(script, timeout=90) or []
    toks = [t.lower() for t in (names or []) if t]
    out: list[dict] = []
    for item in data:
        dn = str(item.get("DisplayName") or "").strip()
        if not dn:
            continue
        if toks and not any(t in dn.lower() for t in toks):
            continue
        out.append(
            {
                "name": dn,
                "direction": str(item.get("Direction") or ""),
                "action": str(item.get("Action") or ""),
                "enabled": bool(item.get("Enabled")),
                "profile": str(item.get("Profile") or ""),
                # Removing any rule needs elevation.
                "removable": False,
                "needs_admin": True,
            }
        )
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_firewall_rule(name: str, dest_dir) -> dict:
    """Dump one rule's full definition so it can be recreated later."""
    dest = Path(dest_dir)
    dest.parent.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:80] or "rule"
    target = dest / f"{safe}.json"
    script = (
        f"$n='{name.replace(chr(39), chr(39)*2)}';"
        f"$out='{str(target).replace(chr(39), chr(39)*2)}';"
        "$r=Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue;"
        "if(-not $r){'NONE'} else {"
        " $r | Select-Object * -ExcludeProperty CimClass,CimInstanceProperties,"
        "CimSystemProperties,PSComputerName | ConvertTo-Json -Depth 3 |"
        " Set-Content -Path $out -Encoding UTF8; 'OK' }"
    )
    res = run_powershell(script, timeout=60).strip()
    ok = "OK" in res
    return {"ok": ok, "path": str(target),
            "error": "" if ok else f"导出规则失败：{name}"}


# --------------------------------------------------------------------------
# Shortcuts
# --------------------------------------------------------------------------

_SHORTCUT_DIRS = (
    lambda: roaming_appdata() / "Microsoft" / "Windows" / "Start Menu" / "Programs",
    lambda: program_data() / "Microsoft" / "Windows" / "Start Menu" / "Programs",
    lambda: Path("C:/Users/Public/Desktop"),
)


def shortcuts() -> list[dict]:
    """Start Menu and Desktop shortcuts, with their resolved targets.

    The target matters: a shortcut is only a leftover when the program it
    points at is gone. A live shortcut to an installed app is not residue.
    """
    script_parts = []
    for fn in _SHORTCUT_DIRS:
        try:
            p = fn()
        except Exception:
            continue
        script_parts.append(str(p))
    if not script_parts:
        return []
    dirs = ";".join("'" + p.replace("'", "''") + "'" for p in script_parts)
    script = (
        f"$dirs=@({dirs});"
        "$sh=New-Object -ComObject WScript.Shell;"
        "$out=@();"
        "foreach($d in $dirs){ if(-not (Test-Path $d)){continue};"
        " Get-ChildItem $d -Recurse -Filter *.lnk -ErrorAction SilentlyContinue |"
        " ForEach-Object { $t=''; try{$t=$sh.CreateShortcut($_.FullName).TargetPath}"
        "catch{}; $out += [pscustomobject]@{"
        " Name=$_.Name; Path=$_.FullName; Target=$t;"
        " TargetExists=($t -ne '' -and (Test-Path $t)) } } };"
        "$out | ConvertTo-Json -Compress"
    )
    data = _ps_json(script, timeout=90) or []
    out: list[dict] = []
    for item in data:
        p = str(item.get("Path") or "")
        if not p:
            continue
        out.append(
            {
                "name": str(item.get("Name") or Path(p).name),
                "path": p,
                "target": str(item.get("Target") or ""),
                "target_exists": bool(item.get("TargetExists")),
                # A shortcut whose target is gone is a genuine leftover and is
                # safe to remove; one pointing at a live program is not.
                "orphan": not bool(item.get("TargetExists")),
                "removable": True,
                "needs_admin": "ProgramData" in p or "Public" in p,
            }
        )
    out.sort(key=lambda x: (not x["orphan"], x["name"].lower()))
    return out


# --------------------------------------------------------------------------
# Services / scheduled tasks / autostart
# --------------------------------------------------------------------------


def services() -> list[dict]:
    script = (
        "Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | "
        "Select-Object Name,DisplayName,State,PathName,StartMode | "
        "ConvertTo-Json -Compress"
    )
    data = _ps_json(script, timeout=90) or []
    out = []
    for item in data:
        out.append(
            {
                "name": str(item.get("Name") or ""),
                "display_name": str(item.get("DisplayName") or ""),
                "state": str(item.get("State") or ""),
                "path": str(item.get("PathName") or ""),
                "start_mode": str(item.get("StartMode") or ""),
                "needs_admin": True,
                "removable": False,
            }
        )
    return out


def scheduled_tasks() -> list[dict]:
    script = (
        "Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {"
        " [pscustomobject]@{ TaskName=$_.TaskName; TaskPath=$_.TaskPath;"
        " State=[string]$_.State;"
        " Execute=($_.Actions | ForEach-Object { $_.Execute }) -join '|' } } |"
        " ConvertTo-Json -Compress"
    )
    data = _ps_json(script, timeout=90) or []
    out = []
    for item in data:
        out.append(
            {
                "name": str(item.get("TaskName") or ""),
                "path": str(item.get("TaskPath") or ""),
                "state": str(item.get("State") or ""),
                "execute": str(item.get("Execute") or ""),
                "needs_admin": True,
                "removable": False,
            }
        )
    return out


def autostart_entries() -> list[dict]:
    """Run-key entries, with their command lines resolved."""
    keys = (
        r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    )
    quoted = ",".join("'" + k + "'" for k in keys)
    script = (
        f"$ks=@({quoted}); $out=@();"
        "foreach($k in $ks){ $p=Get-ItemProperty $k -ErrorAction SilentlyContinue;"
        " if($p){ $p.PSObject.Properties | Where-Object {$_.Name -notlike 'PS*'} |"
        " ForEach-Object { $out += [pscustomobject]@{ Key=$k; Name=$_.Name;"
        " Value=[string]$_.Value } } } };"
        "$out | ConvertTo-Json -Compress"
    )
    data = _ps_json(script, timeout=60) or []
    out = []
    for item in data:
        key = str(item.get("Key") or "")
        out.append(
            {
                "key": key,
                "name": str(item.get("Name") or ""),
                "value": str(item.get("Value") or ""),
                "hive": "HKCU" if key.upper().startswith("HKCU") else "HKLM",
                "needs_admin": not key.upper().startswith("HKCU"),
                "removable": key.upper().startswith("HKCU"),
            }
        )
    return out


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------


def _matches(text: str, tokens: list[str]) -> bool:
    low = (text or "").lower()
    return any(t and t in low for t in tokens)


def inventory_for(label: str, aliases: list[str] | None = None,
                  extra_paths: list[str] | None = None) -> dict:
    """Everything on the Windows side that mentions this agent.

    `extra_paths` lets the caller pass install directories so autostart and
    service command lines can be matched by path as well as by name.
    """
    tokens = [t.lower() for t in str(label).lower().split() if len(t) > 2]
    if aliases:
        tokens += [a.lower() for a in aliases if a]
    path_tokens = [str(p).lower() for p in (extra_paths or []) if p]

    def _hit(text: str) -> bool:
        return _matches(text, tokens) or _matches(text, path_tokens)

    entries = uninstall_entries()
    uninst = match_entry(entries, label, aliases)

    vkeys = [k for k in vendor_keys() if _hit(k["name"])]
    fw = [r for r in firewall_rules() if _hit(r["name"])]
    links = [s for s in shortcuts() if _hit(s["name"]) or _hit(s["target"])]
    svcs = [s for s in services()
            if _hit(s["display_name"]) or _hit(s["name"]) or _hit(s["path"])]
    tasks = [t for t in scheduled_tasks()
             if _hit(t["name"]) or _hit(t["execute"])]
    auto = [a for a in autostart_entries() if _hit(a["name"]) or _hit(a["value"])]

    removable_vkeys = [k for k in vkeys if k.get("removable")]
    blocked_vkeys = [k for k in vkeys if not k.get("removable")]

    return {
        "label": label,
        "tokens": sorted(set(tokens)),
        "uninstall": uninst,
        "registry_keys": vkeys,
        "removable_registry_keys": removable_vkeys,
        "blocked_registry_keys": blocked_vkeys,
        "firewall": fw,
        "shortcuts": links,
        "services": svcs,
        "scheduled_tasks": tasks,
        "autostart": auto,
        "counts": {
            "registry_keys": len(vkeys),
            "removable_registry_keys": len(removable_vkeys),
            "firewall": len(fw),
            "shortcuts": len(links),
            "orphan_shortcuts": sum(1 for s in links if s["orphan"]),
            "services": len(svcs),
            "scheduled_tasks": len(tasks),
            "autostart": len(auto),
        },
        "needs_admin": bool(
            blocked_vkeys or fw or svcs
            or [t for t in tasks if t.get("needs_admin")]
            or [a for a in auto if a.get("needs_admin")]
        ),
    }


def is_elevated() -> bool:
    """Whether this process can write HKLM and firewall rules."""
    script = (
        "$id=[Security.Principal.WindowsIdentity]::GetCurrent();"
        "$p=New-Object Security.Principal.WindowsPrincipal($id);"
        "if($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
        "{'YES'}else{'NO'}"
    )
    return "YES" in run_powershell(script, timeout=30)


def environment_summary() -> dict:
    """Where this machine keeps things, so the UI can explain a path."""
    return {
        "home": str(home()),
        "local_appdata": str(local_appdata()),
        "roaming_appdata": str(roaming_appdata()),
        "program_data": str(program_data()),
        "elevated": is_elevated(),
    }
