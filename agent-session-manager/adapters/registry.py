"""Adapter registry: discovery of which agents exist on this machine.

Detection uses three independent signals so a missing dot-folder does not mean
"not installed":

  1. the adapter's own storage roots exist on disk;
  2. the agent appears in the Windows uninstall registry (gives InstallLocation);
  3. the agent's executable is on PATH or a known install directory exists.

A registry entry is reported even when no adapter claims it, so the UI can show
"installed but not yet supported" instead of silently ignoring it.
"""

from __future__ import annotations

import json
from pathlib import Path

from adapters.antigravity import AntigravityAdapter
from adapters.base import Adapter
from adapters.codebuddy import CodeBuddyAdapter
from adapters.copilot_chat import CopilotChatAdapter
from adapters.dsh import DshAdapter
from adapters.workbuddy import WorkBuddyAdapter
from core.util import home, roaming_appdata, run_powershell

#: Order matters only for display.
ADAPTER_CLASSES: list[type[Adapter]] = [
    DshAdapter,
    WorkBuddyAdapter,
    CodeBuddyAdapter,
    CopilotChatAdapter,
    AntigravityAdapter,
]


def all_adapters() -> list[Adapter]:
    return [cls() for cls in ADAPTER_CLASSES]


def get_adapter(agent_id: str) -> Adapter | None:
    for a in all_adapters():
        if a.id == agent_id:
            return a
    return None


# --------------------------------------------------------------------------
# Registry / installation detection
# --------------------------------------------------------------------------

_UNINSTALL_KEYS = (
    r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    r"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
)

#: Substrings that mark a registry entry as "an AI agent product".
_AGENT_HINTS = (
    "deepseek harness",
    "workbuddy",
    "codebuddy",
    "copilot",
    "antigravity",
    "claude",
    "codex",
    "cursor",
    "gemini",
    "cline",
    "windsurf",
    "trae",
    "qoder",
    "kimi",
    "z code",
    "opencode",
    "aider",
)


_PROGRAMS_CACHE: dict = {"at": 0.0, "data": None}
_PROGRAMS_TTL = 300.0


def installed_programs(force: bool = False) -> list[dict]:
    """Installed applications relevant to AI agents, from the registry.

    Uses PowerShell because the stdlib cannot read the registry. The result is
    cached for five minutes: it costs ~1.4 s and only changes when the user
    installs or removes software. Failure is tolerated -- the caller falls back
    to filesystem detection.
    """
    import time as _t

    now = _t.time()
    if not force and _PROGRAMS_CACHE["data"] is not None:
        if (now - _PROGRAMS_CACHE["at"]) < _PROGRAMS_TTL:
            return _PROGRAMS_CACHE["data"]

    # Registry paths are built as PowerShell single-quoted strings. repr() must
    # NOT be used here: it escapes each backslash ("HKLM:\\SOFTWARE"), which
    # PowerShell treats as a literal double backslash and silently matches
    # nothing.
    quoted = ",".join("'" + p.replace("'", "''") + "'" for p in _UNINSTALL_KEYS)
    script = (
        f"$paths=@({quoted});"
        "Get-ItemProperty $paths -ErrorAction SilentlyContinue | "
        "Where-Object {$_.DisplayName} | "
        "Select-Object DisplayName,DisplayVersion,InstallLocation,Publisher | "
        "ConvertTo-Json -Compress"
    )
    raw = run_powershell(script, timeout=90).strip()
    if not raw:
        return _PROGRAMS_CACHE["data"] or []
    try:
        data = json.loads(raw)
    except ValueError:
        return _PROGRAMS_CACHE["data"] or []
    if isinstance(data, dict):
        data = [data]

    found: list[dict] = []
    seen: set[str] = set()
    for item in data:
        name = (item.get("DisplayName") or "").strip()
        if not name:
            continue
        low = name.lower()
        if not any(h in low for h in _AGENT_HINTS):
            continue
        if low in seen:
            continue
        seen.add(low)
        found.append(
            {
                "name": name,
                "version": item.get("DisplayVersion") or "",
                "location": item.get("InstallLocation") or "",
                "publisher": item.get("Publisher") or "",
            }
        )
    found.sort(key=lambda x: x["name"].lower())
    _PROGRAMS_CACHE["data"] = found
    _PROGRAMS_CACHE["at"] = now
    return found


# --------------------------------------------------------------------------
# Agents we know about but do not support yet (shown as informational)
# --------------------------------------------------------------------------

KNOWN_UNSUPPORTED: list[dict] = [
    {
        "id": "claude-code",
        "label": "Claude Code",
        "storage_hint": "~/.claude",
        "paths": ["~/.claude", "~/.claude.json"],
        "note": "未在本机检测到。若安装后出现，可通过适配器模板扩展。",
    },
    {
        "id": "codex",
        "label": "Codex CLI",
        "storage_hint": "~/.codex",
        "paths": ["~/.codex"],
        "note": "未在本机检测到。",
    },
    {
        "id": "gemini-cli",
        "label": "Gemini CLI",
        "storage_hint": "~/.gemini",
        "paths": ["~/.gemini"],
        "note": "未在本机检测到。",
    },
    {
        "id": "cursor",
        "label": "Cursor",
        "storage_hint": "%APPDATA%/Cursor",
        "paths": ["%APPDATA%/Cursor"],
        "note": "未在本机检测到。",
    },
]

_CLI_PROBES = ("claude", "codex", "gemini", "cursor-agent", "copilot", "opencode", "aider", "cline")


def cli_agents_on_path() -> list[str]:
    from core.util import which

    return [c for c in _CLI_PROBES if which(c)]


# --------------------------------------------------------------------------
# Footprint cache
# --------------------------------------------------------------------------
# Measuring an agent's directory tree is the most expensive thing this tool
# does (~30k files for WorkBuddy). The size only changes when the user runs the
# agent or deletes something, so a short cache keeps the UI responsive while
# still being accurate for a refresh a minute later.

_FOOTPRINT_CACHE: dict[str, tuple[float, tuple[int, int]]] = {}
_FOOTPRINT_TTL = 60.0


def footprint_cached(adapter, force: bool = False) -> tuple[int, int]:
    import time as _t

    key = adapter.id
    now = _t.time()
    hit = _FOOTPRINT_CACHE.get(key)
    if not force and hit and (now - hit[0]) < _FOOTPRINT_TTL:
        return hit[1]
    value = adapter.footprint()
    _FOOTPRINT_CACHE[key] = (now, value)
    return value


def invalidate_footprint() -> None:
    _FOOTPRINT_CACHE.clear()


# --------------------------------------------------------------------------
# Full report
# --------------------------------------------------------------------------


def build_report(include_sizes: bool = True, force_sizes: bool = False) -> dict:
    """Everything the UI needs to render the overview page."""
    adapters = all_adapters()
    agents: list[dict] = []

    for a in adapters:
        exists = a.detect()
        roots = [str(p) for p in a.roots()]
        existing = [str(p) for p in a.existing_roots()]
        if include_sizes and exists:
            size, files = footprint_cached(a, force=force_sizes)
        else:
            size, files = 0, 0
        entry = {
            "id": a.id,
            "label": a.label,
            "installed": exists,
            "can_delete": a.can_delete,
            "storage_hint": a.storage_hint,
            "roots": roots,
            "existing_roots": existing,
            "size": size,
            "file_count": files,
            "processes": list(a.processes),
            "running": a.is_running() if exists else [],
            "session_count": None,
        }
        agents.append(entry)

    # Installed programs from the registry, matched to adapters where possible.
    progs = installed_programs()
    matched_names: set[str] = set()
    for a, entry in zip(adapters, agents):
        label_low = a.label.lower()
        for p in progs:
            pl = p["name"].lower()
            if any(tok in pl for tok in label_low.split()) and len(label_low.split()[0]) > 3:
                entry.setdefault("registry", []).append(p)
                matched_names.add(p["name"])

    unsupported: list[dict] = []
    for p in progs:
        if p["name"] in matched_names:
            continue
        unsupported.append({**p, "supported": False})

    # Known-but-absent agents, only reported when they really are absent.
    absent: list[dict] = []
    for k in KNOWN_UNSUPPORTED:
        any_exists = False
        for raw in k["paths"]:
            p = raw.replace("%APPDATA%", str(roaming_appdata()))
            p = p.replace("~", str(home()))
            if Path(p).exists():
                any_exists = True
                break
        if any_exists:
            unsupported.append(
                {
                    "name": k["label"],
                    "version": "",
                    "location": k["storage_hint"],
                    "publisher": "",
                    "supported": False,
                }
            )
        else:
            absent.append(k)

    detected = [a for a in agents if a["installed"]]
    return {
        "agents": agents,
        "detected_count": len(detected),
        "total_supported": len(adapters),
        "registry_programs": progs,
        "unsupported_programs": unsupported,
        "absent_known": absent,
        "cli_on_path": cli_agents_on_path(),
        "home": str(home()),
    }
