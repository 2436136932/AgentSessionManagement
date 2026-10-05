"""Quarantine retention policy.

Every deletion lands in ``_data/quarantine/<op-id>/`` so it can be restored.
That is what makes the tool safe -- but it is also unbounded. Deleting a
single 483 MB bundled-binary directory would park it in the quarantine
forever, and the "safe" tool would slowly become the largest thing on disk.

This module owns the policy that keeps the quarantine honest:

  * a **retention window** (default 7 days) after which an entry is eligible
    for purging
  * a **total size cap** (default 2 GB) that, when exceeded, evicts the oldest
    entries first regardless of age
  * a **manual purge** that never touches entries younger than a grace period,
    so a user cannot destroy their own undo buffer by clicking too fast

Purge is the *only* destructive action here, and it is always the last resort:
it runs on data the user already chose to delete, never on live agent data.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

from core.util import (
    data_root,
    dir_size,
    human_size,
    read_json,
    remove_tree,
    write_json_atomic,
)

_LOCK = threading.RLock()
_CONFIG_FILE = "quarantine-policy.json"

#: Defaults. Chosen so the quarantine survives long enough to notice a mistake
#: (a week) without being able to grow without bound (2 GB).
DEFAULT_POLICY = {
    "retention_days": 7,
    "max_bytes": 2 * 1024 * 1024 * 1024,
    "grace_hours": 1,
    "enabled": True,
}


def _config_path() -> Path:
    return data_root() / _CONFIG_FILE


def policy() -> dict:
    """Current policy, with defaults filled in for any missing key."""
    with _LOCK:
        data = read_json(_config_path(), None)
        out = dict(DEFAULT_POLICY)
        if isinstance(data, dict):
            for k, v in data.items():
                if k in DEFAULT_POLICY:
                    out[k] = v
        return out


def set_policy(**changes) -> dict:
    """Update the policy. Only known keys with sane types are accepted."""
    with _LOCK:
        cur = policy()
        for k, v in changes.items():
            if k not in DEFAULT_POLICY:
                continue
            if k == "enabled":
                cur[k] = bool(v)
            else:
                try:
                    n = int(v)
                except (TypeError, ValueError):
                    continue
                if n < 0:
                    continue
                # Guard against a zero cap that would purge everything the
                # moment anything is deleted.
                if k == "max_bytes" and n < 16 * 1024 * 1024:
                    continue
                cur[k] = n
        write_json_atomic(_config_path(), cur)
        return cur


# --------------------------------------------------------------------------
# Inventory of quarantine entries
# --------------------------------------------------------------------------


def _op_index() -> dict[str, dict]:
    """{op_id: journal record} for every operation that ever ran."""
    from core.util import journal_path, read_jsonl

    out: dict[str, dict] = {}
    for rec in read_jsonl(journal_path()):
        op = rec.get("op_id")
        if op:
            out[op] = rec
    return out


def entries() -> list[dict]:
    """Every quarantine entry, newest first, with its restore status."""
    from core.util import quarantine_root

    root = quarantine_root()
    try:
        dirs = [p for p in root.iterdir() if p.is_dir()]
    except OSError:
        return []

    index = _op_index()
    out: list[dict] = []
    for d in dirs:
        size, files = dir_size(d)
        try:
            mtime = d.stat().st_mtime
        except OSError:
            mtime = 0.0
        rec = index.get(d.name) or {}
        age_days = (time.time() - mtime) / 86400.0 if mtime else 0.0
        out.append(
            {
                "op_id": d.name,
                "path": str(d),
                "size": size,
                "size_h": human_size(size),
                "file_count": files,
                "mtime": int(mtime * 1000) if mtime else None,
                "age_days": round(age_days, 2),
                "restorable": bool(rec) and not rec.get("quarantine_removed"),
                "agent": rec.get("agent", ""),
                "agent_label": rec.get("agent_label", ""),
                "sid": rec.get("sid", ""),
                "title": rec.get("title", ""),
                "operation_time": rec.get("time"),
                "permanent": rec.get("permanent", False),
                "status": rec.get("status", ""),
            }
        )
    out.sort(key=lambda x: -(x["mtime"] or 0))
    return out


def stats() -> dict:
    """Headline numbers plus which entries the policy would evict."""
    pol = policy()
    ents = entries()
    total = sum(e["size"] for e in ents)
    cutoff_ms = (time.time() - pol["retention_days"] * 86400) * 1000

    aged = [e for e in ents if e["mtime"] and e["mtime"] < cutoff_ms]
    aged_bytes = sum(e["size"] for e in aged)

    # Over-cap eviction: oldest first, until the total fits.
    over = max(0, total - pol["max_bytes"])
    evict: list[dict] = []
    freed = 0
    if over:
        for e in sorted(ents, key=lambda x: (x["mtime"] or 0)):
            if freed >= over:
                break
            evict.append(e)
            freed += e["size"]

    return {
        "policy": pol,
        "entry_count": len(ents),
        "total_bytes": total,
        "total_bytes_h": human_size(total),
        "max_bytes_h": human_size(pol["max_bytes"]),
        "usage_pct": round((total / pol["max_bytes"] * 100.0) if pol["max_bytes"] else 0.0, 1),
        "over_cap": over > 0,
        "over_cap_bytes": over,
        "over_cap_bytes_h": human_size(over),
        "expired_count": len(aged),
        "expired_bytes": aged_bytes,
        "expired_bytes_h": human_size(aged_bytes),
        "evict_count": len(evict),
        "evict_bytes": freed,
        "evict_bytes_h": human_size(freed),
        "evict_ids": [e["op_id"] for e in evict],
        "expired_ids": [e["op_id"] for e in aged],
        "entries": ents,
    }


# --------------------------------------------------------------------------
# Preview and purge
# --------------------------------------------------------------------------


def plan_purge(mode: str = "expired") -> dict:
    """What a purge would remove, without removing it.

    Modes:
      ``expired``  older than the retention window
      ``over_cap`` oldest entries until the total fits under the cap
      ``all``      everything past the grace period
    """
    pol = policy()
    ents = entries()
    now = time.time()
    grace_cutoff_ms = (now - pol["grace_hours"] * 3600) * 1000
    retention_cutoff_ms = (now - pol["retention_days"] * 86400) * 1000

    # The grace period applies to every mode: a just-deleted item must remain
    # restorable even if the user immediately purges.
    def _eligible(e: dict) -> bool:
        return bool(e["mtime"]) and e["mtime"] < grace_cutoff_ms

    if mode == "all":
        chosen = [e for e in ents if _eligible(e)]
    elif mode == "over_cap":
        over = max(0, sum(e["size"] for e in ents) - pol["max_bytes"])
        chosen, freed = [], 0
        for e in sorted(ents, key=lambda x: (x["mtime"] or 0)):
            if freed >= over or not _eligible(e):
                continue
            chosen.append(e)
            freed += e["size"]
    else:
        chosen = [e for e in ents if _eligible(e) and e["mtime"] < retention_cutoff_ms]

    total = sum(e["size"] for e in chosen)
    skipped_grace = [
        e for e in ents if e["mtime"] and e["mtime"] >= grace_cutoff_ms
    ]
    return {
        "mode": mode,
        "count": len(chosen),
        "bytes": total,
        "bytes_h": human_size(total),
        "entries": chosen,
        "skipped_grace_count": len(skipped_grace),
        "grace_hours": pol["grace_hours"],
        "note": (
            f"最近 {pol['grace_hours']} 小时内的记录不会被清除，"
            f"以保留撤销能力（当前跳过 {len(skipped_grace)} 项）。"
        ),
    }


def purge(mode: str = "expired", op_ids: list[str] | None = None) -> dict:
    """Permanently remove quarantine entries.

    `op_ids`, when given, restricts the purge to exactly those entries (and
    still honours the grace period). Returns a per-entry result list, so a
    locked file does not silently masquerade as success.
    """
    from core.util import quarantine_root

    pol = policy()
    grace_cutoff_ms = (time.time() - pol["grace_hours"] * 3600) * 1000

    if op_ids:
        by_id = {e["op_id"]: e for e in entries()}
        planned = [by_id[i] for i in op_ids if i in by_id]
    else:
        planned = plan_purge(mode)["entries"]

    root = quarantine_root()
    results: list[dict] = []
    freed = 0
    for e in planned:
        if e["mtime"] and e["mtime"] >= grace_cutoff_ms:
            results.append(
                {"op_id": e["op_id"], "ok": False, "size": e["size"],
                 "error": f"仍在 {pol['grace_hours']} 小时保护期内，已跳过。"}
            )
            continue
        target = root / e["op_id"]
        # Re-verify the target really is a direct child of the quarantine root
        # before removing it: this is the one place a bad op_id could escape.
        try:
            if target.parent.resolve() != root.resolve():
                results.append({"op_id": e["op_id"], "ok": False, "size": e["size"],
                                "error": "路径不在隔离区内，已拒绝。"})
                continue
        except OSError:
            results.append({"op_id": e["op_id"], "ok": False, "size": e["size"],
                            "error": "路径无法解析，已拒绝。"})
            continue

        err = remove_tree(target)
        if err:
            results.append({"op_id": e["op_id"], "ok": False, "size": e["size"],
                            "error": err})
        else:
            freed += e["size"]
            results.append({"op_id": e["op_id"], "ok": True, "size": e["size"],
                            "error": ""})

    ok = sum(1 for r in results if r["ok"])
    return {
        "ok": True,
        "mode": mode,
        "purged": ok,
        "failed": len(results) - ok,
        "freed_bytes": freed,
        "freed_bytes_h": human_size(freed),
        "results": results,
    }


def auto_purge() -> dict:
    """Run the configured policy. Called on startup and after big deletions.

    Deliberately conservative: does nothing unless `enabled`, and never
    touches anything inside the grace period.
    """
    pol = policy()
    if not pol.get("enabled"):
        return {"ok": True, "skipped": True, "reason": "自动清理已关闭。"}

    out: dict = {"ok": True, "steps": []}
    # 1. expired
    exp = plan_purge("expired")
    if exp["count"]:
        out["steps"].append(purge("expired"))
    # 2. still over the cap -> evict oldest
    st = stats()
    if st["over_cap"]:
        out["steps"].append(purge("over_cap"))
    out["stats"] = stats()
    return out
