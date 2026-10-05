"""Inventory: run every adapter and produce one uniform session list.

Results are cached in memory for a short time so the UI stays responsive while
still reflecting deletions immediately (the executor invalidates the cache).
"""

from __future__ import annotations

import threading
import time

from adapters.registry import all_adapters, build_report, invalidate_footprint
from core.model import Session

_LOCK = threading.RLock()
_CACHE: dict = {"at": 0.0, "sessions": [], "report": None}
_TTL = 15.0  # seconds


def invalidate() -> None:
    with _LOCK:
        _CACHE["at"] = 0.0
        _CACHE["sessions"] = []
        _CACHE["report"] = None
    # Directory sizes change when sessions are deleted, so drop those too.
    invalidate_footprint()
    # The content-search index derives from the same stores; keep it honest.
    try:
        from core import search

        search.invalidate()
    except Exception:
        pass


def scan(force: bool = False) -> list[Session]:
    """All sessions from all installed agents."""
    with _LOCK:
        if not force and _CACHE["sessions"] and (time.time() - _CACHE["at"]) < _TTL:
            return _CACHE["sessions"]

        sessions: list[Session] = []
        for a in all_adapters():
            try:
                if not a.detect():
                    continue
                sessions.extend(a.list_sessions())
            except Exception as e:  # an adapter must never break the whole scan
                sessions.append(
                    Session(
                        agent=a.id,
                        agent_label=a.label,
                        sid="__error__",
                        title=f"扫描失败：{type(e).__name__}",
                        note=str(e),
                        deletable=False,
                        is_ghost=True,
                    )
                )
        _CACHE["sessions"] = sessions
        _CACHE["at"] = time.time()
        return sessions


def report(force: bool = False, force_sizes: bool = False) -> dict:
    """Overview data.

    `force` refreshes the session list; directory sizes have their own cache
    (see footprint_cached) because walking ~30k files per agent on every poll
    is wasteful. Sizes are recomputed automatically after a deletion, since
    invalidate() clears that cache.
    """
    with _LOCK:
        if not force and _CACHE["report"] and (time.time() - _CACHE["at"]) < _TTL:
            return _CACHE["report"]
    rep = build_report(force_sizes=force_sizes)
    # Attach per-agent session counts (single scan pass).
    sessions = scan(force=force)
    counts: dict[str, int] = {}
    sizes: dict[str, int] = {}
    for s in sessions:
        counts[s.agent] = counts.get(s.agent, 0) + 1
        sizes[s.agent] = sizes.get(s.agent, 0) + s.size
    for entry in rep["agents"]:
        entry["session_count"] = counts.get(entry["id"], 0)
        entry["session_bytes"] = sizes.get(entry["id"], 0)
    with _LOCK:
        _CACHE["report"] = rep
    return rep


def sessions_for(agent_id: str) -> list[Session]:
    return [s for s in scan() if s.agent == agent_id]


def find(agent_id: str, sid: str) -> Session | None:
    for s in scan():
        if s.agent == agent_id and s.sid == sid:
            return s
    return None


def health(force: bool = False) -> list[dict]:
    """Cleanup findings from every installed adapter."""
    findings: list[dict] = []
    for a in all_adapters():
        try:
            if not a.detect():
                continue
            findings.extend(a.health())
        except Exception:
            continue
    return findings


# --------------------------------------------------------------------------
# Extra: reclaimable items that are not agent sessions but are plainly junk.
# These are *suggestions only* -- the executor never touches a path that is not
# produced by an adapter plan, so this list is reported, not auto-deleted.
# --------------------------------------------------------------------------

RECLAIMABLE_HINTS = [
    {
        "id": "genie-updater",
        "label": "@genieworkbuddy-desktop-updater 残留安装包",
        "rel": r"@genieworkbuddy-desktop-updater",
        "why": "应用内升级下载的安装包，升级完成后不再需要。",
    },
    {
        "id": "dsh-updater",
        "label": "@deepseek-aidsh-desktop-updater 残留安装包",
        "rel": r"@deepseek-aidsh-desktop-updater",
        "why": "应用内升级下载的安装包，升级完成后不再需要。",
    },
]


def reclaimable() -> list[dict]:
    """Large leftover installer folders, reported for manual review."""
    from pathlib import Path

    from core.util import dir_size, local_appdata

    out: list[dict] = []
    base = local_appdata()
    for h in RECLAIMABLE_HINTS:
        p = Path(h["rel"]) if Path(h["rel"]).is_absolute() else base / h["rel"]
        if not p.exists():
            continue
        size, files = dir_size(p)
        out.append(
            {
                "id": h["id"],
                "label": h["label"],
                "path": str(p),
                "why": h["why"],
                "size": size,
                "file_count": files,
            }
        )
    out.sort(key=lambda x: -x["size"])
    return out
