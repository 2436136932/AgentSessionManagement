"""Footprint history: one snapshot per hour, so growth can be shown and predicted.

Each snapshot records the on-disk footprint (bytes and file count) of every
installed adapter. Snapshots are appended to `<data_root>/history.jsonl`, one
JSON object per line, which keeps the write path cheap and the file readable by
hand. A line-based log is deliberate: a snapshot is a few hundred bytes, there
may be thousands of them, and a crash costs at most the last line.

Three consumers are supported:

  * `series()`   -- the raw points, for a growth chart;
  * `trend()`    -- a least-squares fit plus a "when will it cross the target"
                    estimate, so the number shown to the user is derived from
                    the whole history rather than from two arbitrary samples;
  * `summarize()` -- a per-agent overview for the dashboard.

Honesty rules: a trend needs at least three points before it is reported as
usable, and a projection is only offered when growth is genuinely positive.
A number that is not supported by the data is withheld with an explanation
rather than shown as if it were measured.
"""

from __future__ import annotations

import json
import math
import os
import tempfile
import threading
from pathlib import Path

from adapters.registry import all_adapters
from core.util import (
    append_jsonl,
    data_root,
    human_size,
    ms_to_iso,
    now_ms,
    read_jsonl,
)

try:  # The registry cache is a pure speed-up; older registries lack it.
    from adapters.registry import footprint_cached as _footprint_cached
except Exception:  # pragma: no cover - defensive against an older registry
    _footprint_cached = None

#: All file access goes through this lock: record/prune rewrite the whole file.
_LOCK = threading.RLock()

#: Minimum spacing between automatic snapshots (1 hour).
MIN_INTERVAL_MS = 3_600_000

#: One day in milliseconds; the unit of every trend calculation.
DAY_MS = 86_400_000

#: Hard cap on the number of stored snapshots, enforced while appending.
MAX_LINES = 20_000

#: Fewer points than this cannot support a trend claim.
MIN_POINTS = 3

#: The footprint threshold the projection aims at: 5 GiB.
GROWTH_TARGET_BYTES = 5 * 1024 ** 3

_FILE = "history.jsonl"


# --------------------------------------------------------------------------
# File access (always under _LOCK)
# --------------------------------------------------------------------------


def _path() -> Path:
    return data_root() / _FILE


def _read_rows() -> list[dict]:
    """Every stored snapshot, oldest first. Malformed lines are dropped."""
    rows = [r for r in read_jsonl(_path()) if isinstance(r, dict)]
    rows = [r for r in rows if isinstance(r.get("at"), (int, float))]
    rows.sort(key=lambda r: r["at"])
    return rows


def _write_rows(rows: list[dict]) -> None:
    """Replace the whole file atomically (temp file in the same directory).

    A rewrite is used instead of a truncating open so an interrupted prune or
    cap can never leave a half-written history behind: `os.replace` either
    swaps in the complete new file or changes nothing.
    """
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-history-", suffix=".jsonl")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _newest_at(rows: list[dict]) -> int:
    if not rows:
        return 0
    try:
        return int(max(r["at"] for r in rows))
    except (KeyError, TypeError, ValueError):
        return 0


# --------------------------------------------------------------------------
# Snapshotting
# --------------------------------------------------------------------------


def _measure(adapter) -> tuple[int, int] | None:
    """(bytes, files) for one adapter, or None when it cannot be measured."""
    try:
        if _footprint_cached is not None:
            size, files = _footprint_cached(adapter)
        else:
            size, files = adapter.footprint()
        return int(size or 0), int(files or 0)
    except Exception:
        return None


def _snapshot() -> dict:
    """Measure every installed adapter. One broken adapter is skipped, not fatal."""
    agents: dict[str, dict] = {}
    for a in all_adapters():
        try:
            if not a.detect():
                continue
        except Exception:
            continue
        measured = _measure(a)
        if measured is None:
            continue
        size, files = measured
        agents[str(a.id)] = {"bytes": size, "files": files}
    return {"at": now_ms(), "agents": agents}


def record(force: bool = False) -> dict:
    """Append one footprint snapshot, at most once per hour unless forced.

    Returns the snapshot that was written, or `{"recorded": False, "reason": ...}`
    when the rate limit applied.
    """
    with _LOCK:
        rows = _read_rows()
        newest = _newest_at(rows)
        if not force and newest:
            age = now_ms() - newest
            if age < MIN_INTERVAL_MS:
                minutes = max(0, age) // 60_000
                return {
                    "recorded": False,
                    "reason": (
                        f"距上次记录仅 {minutes} 分钟，未满 "
                        f"{MIN_INTERVAL_MS // 60_000} 分钟，本次已跳过；"
                        "如需强制记录请使用 force=True。"
                    ),
                }

        snap = _snapshot()
        if len(rows) + 1 > MAX_LINES:
            # Cap reached: keep the most recent lines and rewrite atomically.
            rows = rows[-(MAX_LINES - 1):]
            rows.append(snap)
            _write_rows(rows)
        else:
            append_jsonl(_path(), snap)
        return {"recorded": True, "at": snap["at"], "agents": snap["agents"]}


# --------------------------------------------------------------------------
# Reading series
# --------------------------------------------------------------------------


def _points(rows: list[dict], agent_id: str, cutoff: int = 0) -> list[dict]:
    """Points for one agent (or the total) from already-read rows."""
    out: list[dict] = []
    for row in rows:
        at = row.get("at")
        if at is None:
            continue
        try:
            at = int(at)
        except (TypeError, ValueError):
            continue
        if at < cutoff:
            continue
        agents = row.get("agents")
        if not isinstance(agents, dict):
            agents = {}
        if agent_id:
            entry = agents.get(agent_id)
            # Snapshots taken before an agent was installed carry no key for
            # it; counting those as zeros would fake a growth curve.
            if not isinstance(entry, dict):
                continue
            size = int(entry.get("bytes") or 0)
            files = int(entry.get("files") or 0)
        else:
            size = 0
            files = 0
            for entry in agents.values():
                if isinstance(entry, dict):
                    size += int(entry.get("bytes") or 0)
                    files += int(entry.get("files") or 0)
        out.append({"at": at, "at_iso": ms_to_iso(at), "bytes": size, "files": files})
    return out


def series(agent_id: str = "", days: int = 90) -> dict:
    """Points for one agent, or the total across agents, over the last `days`."""
    aid = (agent_id or "").strip()
    try:
        span = max(0, int(days))
        cutoff = now_ms() - span * DAY_MS
        return {"points": _points(_read_rows(), aid, cutoff), "agent": aid}
    except Exception as e:  # never raise out of a read path
        return {
            "points": [],
            "agent": aid,
            "note": f"读取历史数据失败：{type(e).__name__}。",
        }


# --------------------------------------------------------------------------
# Trend
# --------------------------------------------------------------------------


def _per_day(points: list[dict]) -> float:
    """Least-squares slope in bytes per day (x = days since the first point).

    Returns 0.0 when the fit is undefined (fewer than two points, or every
    point at the same instant), which keeps callers free of division guards.
    """
    n = len(points)
    if n < 2:
        return 0.0
    x0 = points[0]["at"]
    xs = [(p["at"] - x0) / DAY_MS for p in points]
    ys = [float(p["bytes"]) for p in points]
    mx = sum(xs) / n
    my = sum(ys) / n
    denom = sum((x - mx) ** 2 for x in xs)
    if denom <= 0:
        return 0.0
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    return num / denom


def trend(agent_id: str = "", days: int = 30) -> dict:
    """Least-squares growth estimate plus a projection to the target size."""
    aid = (agent_id or "").strip()
    out: dict = {
        "agent": aid,
        "points": 0,
        "first_bytes": 0,
        "last_bytes": 0,
        "delta_bytes": 0,
        "delta_bytes_h": human_size(0),
        "per_day_bytes": 0.0,
        "per_day_bytes_h": human_size(0),
        "projection_days": None,
        "projection_target_bytes": GROWTH_TARGET_BYTES,
        "insufficient": True,
        "note": "",
    }
    try:
        points = series(aid, days).get("points") or []
        n = len(points)
        out["points"] = n
        if not points:
            out["note"] = "暂无历史快照，无法估算趋势。请先记录快照（record）。"
            return out

        first, last = points[0], points[-1]
        out["first_bytes"] = int(first["bytes"])
        out["last_bytes"] = int(last["bytes"])
        out["delta_bytes"] = out["last_bytes"] - out["first_bytes"]
        out["delta_bytes_h"] = human_size(out["delta_bytes"])

        slope = _per_day(points)
        out["per_day_bytes"] = round(slope, 2)
        out["per_day_bytes_h"] = human_size(slope)
        out["insufficient"] = n < MIN_POINTS

        notes: list[str] = []
        if out["insufficient"]:
            notes.append(f"数据点不足（当前 {n} 个），至少需要 3 个才能估算趋势。")

        remaining = GROWTH_TARGET_BYTES - out["last_bytes"]
        if slope <= 0:
            # Guard against a negative or zero slope before dividing: a
            # projection here would be a fabricated number.
            notes.append(
                "增长趋势非正（当前未观察到持续增长），因此不预估达到 "
                f"{human_size(GROWTH_TARGET_BYTES)} 的时间。"
            )
        elif remaining <= 0:
            out["projection_days"] = 0
            notes.append(f"当前占用已达到 {human_size(GROWTH_TARGET_BYTES)}。")
        elif out["insufficient"]:
            notes.append("数据点太少，暂不预估达标时间。")
        else:
            out["projection_days"] = int(math.ceil(remaining / slope))
            notes.append(
                f"按当前趋势（约 {human_size(slope)}/天），预计约 "
                f"{out['projection_days']} 天后达到 {human_size(GROWTH_TARGET_BYTES)}。"
            )
        out["note"] = "".join(notes)
        return out
    except Exception as e:  # never raise out of a read path
        out["note"] = f"估算趋势失败：{type(e).__name__}。"
        return out


# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------


def _labels() -> dict[str, str]:
    """agent id -> human label, from the registry when it is reachable."""
    out: dict[str, str] = {}
    try:
        for a in all_adapters():
            out[str(a.id)] = str(a.label or a.id)
    except Exception:
        pass
    return out


def summarize() -> dict:
    """Per-agent overview of the stored history."""
    out: dict = {
        "snapshots": 0,
        "first_at": None,
        "last_at": None,
        "span_days": 0.0,
        "agents": [],
        "note": "",
    }
    try:
        rows = _read_rows()
        out["snapshots"] = len(rows)
        if not rows:
            out["note"] = "暂无历史快照。"
            return out

        ats = [int(r["at"]) for r in rows]
        first_at, last_at = min(ats), max(ats)
        out["first_at"] = first_at
        out["last_at"] = last_at
        out["span_days"] = round((last_at - first_at) / DAY_MS, 2)

        labels = _labels()
        seen: list[str] = []
        for row in rows:
            agents = row.get("agents")
            if not isinstance(agents, dict):
                continue
            for aid in agents:
                if aid not in seen:
                    seen.append(aid)
        # Registry order first, then anything seen only in older snapshots.
        order = [aid for aid in labels if aid in seen]
        order += sorted(a for a in seen if a not in order)

        for aid in order:
            points = _points(rows, aid)
            if not points:
                continue
            first_bytes = int(points[0]["bytes"])
            last_bytes = int(points[-1]["bytes"])
            out["agents"].append(
                {
                    "agent": aid,
                    "label": labels.get(aid, aid),
                    "first_bytes": first_bytes,
                    "last_bytes": last_bytes,
                    "delta_bytes": last_bytes - first_bytes,
                    "per_day_bytes": round(_per_day(points), 2),
                    "insufficient": len(points) < MIN_POINTS,
                }
            )
        return out
    except Exception as e:  # never raise out of a read path
        out["note"] = f"汇总历史数据失败：{type(e).__name__}。"
        return out


# --------------------------------------------------------------------------
# Pruning
# --------------------------------------------------------------------------


def prune(keep_days: int = 365) -> int:
    """Drop snapshots older than `keep_days`; returns how many were removed."""
    with _LOCK:
        rows = _read_rows()
        if not rows:
            return 0
        cutoff = now_ms() - max(0, int(keep_days)) * DAY_MS
        keep = [r for r in rows if int(r["at"]) >= cutoff]
        removed = len(rows) - len(keep)
        if removed:
            _write_rows(keep)
        return removed
