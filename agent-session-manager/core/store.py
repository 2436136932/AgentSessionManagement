"""Persistent user state: pins (keep-protection), tags and notes.

This is the tool's own state, kept in `_data/user-state.json`, never inside an
agent's storage. It is deliberately small and human-readable so a user can
inspect or hand-edit it.

Why a *pin* matters more than it first appears: without it, a bulk delete can
silently remove the one session a person actually cares about. Every adapter
plan is therefore checked against this store and refuses to proceed for a
pinned session unless the caller explicitly overrides.

Atomic writes and a `.bak` sidecar are used so a crash cannot lose the list.
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path

from core.util import data_root, read_json, write_json_atomic

_LOCK = threading.RLock()
_STATE_FILE = "user-state.json"
_SCHEMA = 2


def _path() -> Path:
    return data_root() / _STATE_FILE


def _empty() -> dict:
    return {"version": _SCHEMA, "pins": {}, "tags": {}, "notes": {}, "workspace_pins": {}}


def _norm_path(p: str) -> str:
    """Normalise a workspace path for comparison (case-insensitive on Windows)."""
    import os

    if not p:
        return ""
    try:
        s = os.path.normcase(os.path.normpath(str(p)))
    except (OSError, ValueError):
        return ""
    return s.rstrip("\\/")


def _norm_key(key: str) -> str:
    """Normalise the path portion of a workspace-pin key."""
    agent, _, path = key.partition("\u0000")
    return f"{agent}\u0000{_norm_path(path)}"


def _key(agent: str, sid: str) -> str:
    """Stable composite key. Session ids may contain any character, so the
    agent prefix plus a separator that cannot appear in an agent id is used."""
    return f"{agent}\u0000{sid}"


def split_key(key: str) -> tuple[str, str]:
    agent, _, sid = key.partition("\u0000")
    return agent, sid


# --------------------------------------------------------------------------
# Load / save
# --------------------------------------------------------------------------


def load() -> dict:
    with _LOCK:
        data = read_json(_path(), None)
        if not isinstance(data, dict):
            return _empty()
        # Tolerate an older or partially written file.
        base = _empty()
        for k in ("pins", "tags", "notes", "workspace_pins"):
            v = data.get(k)
            if isinstance(v, dict):
                base[k] = v
        base["version"] = _SCHEMA
        return base


def save(data: dict) -> None:
    with _LOCK:
        data["version"] = _SCHEMA
        write_json_atomic(_path(), data)


# --------------------------------------------------------------------------
# Pins
# --------------------------------------------------------------------------


def pin(agent: str, sid: str, reason: str = "") -> dict:
    with _LOCK:
        d = load()
        d["pins"][_key(agent, sid)] = {
            "reason": reason,
            "at": int(time.time() * 1000),
        }
        save(d)
        return d["pins"][_key(agent, sid)]


def unpin(agent: str, sid: str) -> bool:
    with _LOCK:
        d = load()
        existed = d["pins"].pop(_key(agent, sid), None) is not None
        if existed:
            save(d)
        return existed


def is_pinned(agent: str, sid: str) -> bool:
    return _key(agent, sid) in load()["pins"]


def pin_info(agent: str, sid: str) -> dict | None:
    return load()["pins"].get(_key(agent, sid))


def pinned_map() -> dict[str, dict]:
    """{ "<agent>\0<sid>": {...} } for bulk application to a session list."""
    return load()["pins"]


# --------------------------------------------------------------------------
# Tags and notes
# --------------------------------------------------------------------------


def set_tags(agent: str, sid: str, tags: list[str]) -> list[str]:
    """Replace this session's tags.

    A bare string is rejected rather than iterated: `set_tags(..., "hello")`
    would otherwise silently store one tag per character
    (`['h','e','l','l','o']`), which is exactly the kind of quiet corruption
    that is hard to notice and annoying to undo.
    """
    if isinstance(tags, str) or not isinstance(tags, (list, tuple, set)):
        tags = []
    clean = sorted({str(t).strip() for t in tags if str(t).strip()})[:20]
    with _LOCK:
        d = load()
        k = _key(agent, sid)
        if clean:
            d["tags"][k] = clean
        else:
            d["tags"].pop(k, None)
        save(d)
        return clean


def get_tags(agent: str, sid: str) -> list[str]:
    return list(load()["tags"].get(_key(agent, sid)) or [])


def all_tags() -> list[str]:
    out: set[str] = set()
    for v in load()["tags"].values():
        if isinstance(v, list):
            out.update(str(x) for x in v)
    return sorted(out)


def set_note(agent: str, sid: str, note: str) -> str:
    note = (note or "").strip()[:2000]
    with _LOCK:
        d = load()
        k = _key(agent, sid)
        if note:
            d["notes"][k] = note
        else:
            d["notes"].pop(k, None)
        save(d)
        return note


def get_note(agent: str, sid: str) -> str:
    return str(load()["notes"].get(_key(agent, sid)) or "")


# --------------------------------------------------------------------------
# Bulk decoration
# --------------------------------------------------------------------------


def decorate(session_dicts: list[dict]) -> list[dict]:
    """Attach pinned/tags/note to session dicts in one load, for the UI.

    Also resolves workspace-level protection, so the UI can show *why* a
    session is protected (its own pin, or the folder it lives in).
    """
    d = load()
    pins, tags, notes, wss = d["pins"], d["tags"], d["notes"], d["workspace_pins"]

    # Normalise the workspace pins once, not per session.
    norm_ws: list[tuple[str, str, dict]] = []
    for key, info in wss.items():
        a, _, p = _norm_key(key).partition("\u0000")
        if a and p:
            norm_ws.append((a, p, info))

    for s in session_dicts:
        agent = s.get("agent", "")
        k = _key(agent, s.get("sid", ""))
        info = pins.get(k)
        s["pinned"] = info is not None
        s["pin_reason"] = (info or {}).get("reason", "")
        s["tags"] = list(tags.get(k) or [])
        s["note"] = notes.get(k, "")

        # Workspace protection: longest matching folder wins.
        cwd = _norm_path(s.get("cwd") or "")
        covered: dict | None = None
        best = -1
        if cwd:
            for a, p, winfo in norm_ws:
                if a != agent:
                    continue
                if cwd == p or cwd.startswith(p + os.sep):
                    if len(p) > best:
                        covered, best = winfo, len(p)
        s["workspace_protected"] = covered is not None
        s["workspace_pin_path"] = (covered or {}).get("path", "")
        s["workspace_pin_reason"] = (covered or {}).get("reason", "")
        #: Effective protection: own pin, or the enclosing workspace pin.
        s["protected"] = s["pinned"] or s["workspace_protected"]
    return session_dicts


# --------------------------------------------------------------------------
# Workspace-level pins
# --------------------------------------------------------------------------
# A session pin protects one conversation. A *workspace* pin protects every
# session under a folder -- including ones that do not exist yet -- which is
# the right unit of intent for "this project matters, never clean it up".
# Matching walks up the session's cwd so nested directories are covered.


def pin_workspace(agent: str, path: str, reason: str = "") -> dict:
    key = f"{agent}\u0000{_norm_path(path)}"
    with _LOCK:
        d = load()
        d["workspace_pins"][key] = {
            "agent": agent,
            "path": str(path),
            "reason": reason,
            "at": int(time.time() * 1000),
        }
        save(d)
        return d["workspace_pins"][key]


def unpin_workspace(agent: str, path: str) -> bool:
    key = f"{agent}\u0000{_norm_path(path)}"
    with _LOCK:
        d = load()
        existed = d["workspace_pins"].pop(key, None) is not None
        if existed:
            save(d)
        return existed


def workspace_pins() -> list[dict]:
    return sorted(
        load()["workspace_pins"].values(),
        key=lambda x: (x.get("agent", ""), x.get("path", "")),
    )


def match_workspace(agent: str, cwd: str) -> dict | None:
    """The workspace pin covering this cwd, if any.

    Matches the folder itself and anything beneath it, so pinning
    `E:\\projects\\app` also covers `E:\\projects\\app\\sub`. Falls back to
    walking up the path so a session in a nested subfolder still matches a pin
    on a parent that is a prefix of it.
    """
    target = _norm_path(cwd)
    if not target:
        return None
    pins = load()["workspace_pins"]
    best: dict | None = None
    best_len = -1
    for key, info in pins.items():
        p_agent, _, p_path = _norm_key(key).partition("\u0000")
        if p_agent != agent or not p_path:
            continue
        if target == p_path or target.startswith(p_path + os.sep):
            # Prefer the most specific (longest) matching pin.
            if len(p_path) > best_len:
                best, best_len = info, len(p_path)
    return best


def protection_for(agent: str, sid: str, cwd: str = "") -> dict | None:
    """Why this session is protected, or None. Session pin wins over workspace."""
    info = pin_info(agent, sid)
    if info is not None:
        return {"kind": "session", "reason": info.get("reason", ""), "info": info}
    if cwd:
        ws = match_workspace(agent, cwd)
        if ws is not None:
            return {"kind": "workspace", "reason": ws.get("reason", ""), "info": ws}
    return None


def counts() -> dict:
    d = load()
    return {
        "pins": len(d["pins"]),
        "workspace_pins": len(d["workspace_pins"]),
        "tagged": len(d["tags"]),
        "notes": len(d["notes"]),
        "all_tags": all_tags(),
    }


def stats_for(agent: str, sid: str) -> dict:
    return {
        "pinned": is_pinned(agent, sid),
        "pin_reason": (pin_info(agent, sid) or {}).get("reason", ""),
        "tags": get_tags(agent, sid),
        "note": get_note(agent, sid),
    }
