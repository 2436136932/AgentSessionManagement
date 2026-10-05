"""Group sessions from different Agents by the project folder they worked in.

The inventory lists sessions per agent, which is the wrong axis for the
question a person actually asks: "what is this folder, and who has been
working in it?" One project touched by four different Agents currently appears
as four unrelated rows in four unrelated lists, and the space it really
occupies -- and the cleanup decision it deserves -- is invisible.

This module regroups the same sessions along the working directory they
recorded, so `E:\\work\\thing` used by DSH, CodeBuddy and Copilot becomes one
row with an agent_count of 3. Nothing here reads or writes agent storage: it
transforms `Session.to_dict()` payloads the caller already has, plus optional
score and usage maps keyed by ``"<agent>|<sid>"``.

Two decisions are worth stating because they are visible in the output:

  * **Grouping is by path only, never by title.** Titles across agents are
    unrelated strings; a shared cwd is evidence, a similar title is not.
  * **Keys are conservative.** A wrapper folder such as ``<repo>\\src`` is
    folded into its parent *only* when the parent still exists on disk and
    genuinely looks like a source checkout (``core.ownership``'s marker list).
    Guessing here would merge two unrelated projects, which is worse than
    leaving one project split in two.

Nothing in this module deletes or modifies anything, and no function raises:
on any failure the caller gets a well-formed empty result with a Chinese note.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from core.ownership import SOURCE_REPO_MARKERS
from core.util import human_size, ms_to_iso

#: Trailing segments that are usually a wrapper *inside* a project rather than a
#: project of their own. Only collapsed when the parent is proven to be a repo.
COLLAPSIBLE_SEGMENTS = frozenset(
    {"src", "source", "app", "main", "code", "repo", "project"}
)

#: How many wrapper levels may be folded away at most.
MAX_COLLAPSE = 4

#: Placeholder used when a session recorded no working directory at all. Such
#: sessions are counted as `unassigned`, never invented into a project.
NO_CWD_LABEL = "(未记录工作目录)"

#: "E:", "E:\\", "\\\\server\\share", "\\\\server\\share\\"
_DRIVE_ROOT_RE = re.compile(r"^[a-z]:[\\/]?$")
_UNC_ROOT_RE = re.compile(r"^\\\\[^\\/]+[\\/][^\\/]+[\\/]?$")
_HAS_DRIVE_RE = re.compile(r"^[a-zA-Z]:")

#: Fields kept from each session inside a project. `extra` is deliberately
#: excluded: it holds an adapter's raw dump and can be orders of magnitude
#: larger than everything else in the report combined.
TRIMMED_FIELDS = (
    "agent",
    "agent_label",
    "sid",
    "title",
    "updated_at",
    "updated_iso",
    "size",
    "size_h",
    "pinned",
    "protected",
)

#: Tiers that mean "this session is not worth much".
JUNK_TIERS = ("junk", "low")


# --------------------------------------------------------------------------
# Key normalisation
# --------------------------------------------------------------------------


def _is_root(key: str) -> bool:
    """True for a filesystem root (drive root, UNC share root, POSIX root)."""
    if not key:
        return False
    if key in ("/", "\\"):
        return True
    if _DRIVE_ROOT_RE.match(key):
        return True
    return bool(_UNC_ROOT_RE.match(key))


def _strip_trailing(key: str) -> str:
    if _is_root(key):
        return key
    return key.rstrip("\\/")


def _collapse(key: str) -> str:
    """Fold a trailing wrapper segment into its parent, when that is provable.

    All three conditions must hold, and they are checked against the real
    filesystem -- a path from a deleted folder or another machine simply keeps
    its literal key:

      1. the trailing segment is a known wrapper name (``src``, ``repo``, ...);
      2. the parent directory still exists here;
      3. the parent contains a source-repo marker from ``core.ownership``.
    """
    sep = "\\" if "\\" in key else "/"
    cur = key
    for _ in range(MAX_COLLAPSE):
        if not cur or _is_root(cur):
            break
        idx = cur.rfind(sep)
        if idx <= 0:
            break
        seg = cur[idx + 1:].lower()
        if seg not in COLLAPSIBLE_SEGMENTS:
            break
        parent = cur[:idx]
        if not parent or _is_root(parent) or _DRIVE_ROOT_RE.match(parent):
            break
        try:
            if not os.path.isdir(parent):
                break
            p = Path(parent)
            if not any((p / marker).exists() for marker in SOURCE_REPO_MARKERS):
                break
        except (OSError, ValueError):
            break
        cur = parent
    return cur


def project_key(cwd: str) -> str:
    """Normalise a working directory into a grouping key.

    Blank input gives ``""`` (the session is unassigned). Otherwise the path is
    tilde-expanded, separator-normalised, case-folded and stripped of a
    trailing separator; a drive root such as ``E:\\`` stays a root instead of
    collapsing to an empty string. Finally a trailing wrapper folder is folded
    into its parent when -- and only when -- the parent exists on this machine
    and carries a source-repo marker, so ``<repo>\\src`` and ``<repo>`` group
    together while an unrelated ``E:\\x\\app`` does not.

    Never raises; unusable input simply yields ``""``.
    """
    try:
        raw = "" if cwd is None else str(cwd)
    except Exception:
        return ""
    s = raw.strip().strip('"').strip("'").strip()
    if not s:
        return ""

    # "~" and "~/" must expand before a separator decision is made, because the
    # expansion decides which separator style the path uses.
    try:
        s = os.path.expanduser(s)
    except Exception:
        pass
    if not s.strip():
        return ""

    # A path is treated as Windows-shaped when this host is Windows, when it has
    # a drive letter, or when it already contains a backslash. POSIX-looking
    # paths on a POSIX host keep their case (two folders really can differ only
    # by case there); everywhere else the key is case-folded, which is what
    # makes "E:\\Work" and "e:\\work" one project.
    windows_shaped = (
        os.name == "nt" or bool(_HAS_DRIVE_RE.match(s)) or ("\\" in s)
    )
    if windows_shaped:
        s = s.replace("/", "\\")
    else:
        s = s.replace("\\", "/")

    try:
        s = os.path.normpath(s)
    except (OSError, ValueError):
        pass
    if windows_shaped:
        try:
            s = os.path.normcase(s)
        except Exception:
            s = s.lower()
    if not s or s == ".":
        return ""

    s = _strip_trailing(s)
    if not s:
        return ""
    if _is_root(s):
        return s
    s = _strip_trailing(_collapse(s))
    return s


def label(key: str) -> str:
    """A short human label: the last two segments of the key.

    ``E:\\a\\b\\c`` -> ``b\\c``. A drive root is shown as the drive only
    (``E:\\`` -> ``E:``), and an empty key gets the "no working directory"
    placeholder so a report never renders a blank project name.
    """
    try:
        k = "" if key is None else str(key)
    except Exception:
        return NO_CWD_LABEL
    if not k:
        return NO_CWD_LABEL
    if _DRIVE_ROOT_RE.match(k):
        return k[:2].upper()
    if _UNC_ROOT_RE.match(k):
        parts = [p for p in re.split(r"[\\/]+", k) if p]
        return "\\\\" + "\\".join(parts[-2:]) if parts else k
    if k in ("/", "\\"):
        return k
    sep = "\\" if "\\" in k else "/"
    parts = [p for p in k.split(sep) if p]
    if not parts:
        return k
    if len(parts) == 1:
        return parts[0]
    return sep.join(parts[-2:])


# --------------------------------------------------------------------------
# Grouping
# --------------------------------------------------------------------------


def _empty(note: str) -> dict:
    return {"projects": [], "total_projects": 0, "unassigned": 0, "note": note}


def _score_of(scores: dict, agent: str, sid: str) -> dict:
    try:
        v = scores.get(f"{agent}|{sid}")
    except Exception:
        return {}
    return v if isinstance(v, dict) else {}


def _tokens_of(usage: dict, agent: str, sid: str):
    try:
        v = usage.get(f"{agent}|{sid}")
    except Exception:
        return None
    if not isinstance(v, dict):
        return None
    n = v.get("total_tokens")
    if isinstance(n, bool) or not isinstance(n, (int, float)):
        return None
    return int(n)


def _trim(s: dict, sc: dict, tokens) -> dict:
    """One session as it appears inside a project: display fields only."""
    out: dict = {}
    for f in TRIMMED_FIELDS:
        if f in ("pinned", "protected"):
            out[f] = bool(s.get(f))
        elif f == "size":
            try:
                out[f] = int(s.get(f) or 0)
            except (TypeError, ValueError):
                out[f] = 0
        elif f in ("updated_at",):
            v = s.get(f)
            out[f] = int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None
        elif f == "size_h":
            out[f] = str(s.get(f) or human_size(out.get("size") or 0))
        else:
            out[f] = str(s.get(f) or "")
    score = sc.get("score")
    if isinstance(score, (int, float)) and not isinstance(score, bool):
        out["score"] = int(score)
    tier = sc.get("tier")
    if tier:
        out["tier"] = str(tier)
    if tokens is not None:
        out["total_tokens"] = tokens
    return out


def _activity(s: dict):
    """The timestamp used for first/last: last activity, else creation."""
    for f in ("updated_at", "created_at"):
        v = s.get(f)
        if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0:
            return int(v)
    return None


def _finish(projects: list[dict], unassigned: int, sessions_total: int) -> dict:
    projects.sort(key=lambda p: (-(p.get("total_bytes") or 0),
                                 -(p.get("session_count") or 0)))
    return {
        "projects": projects,
        "total_projects": len(projects),
        "unassigned": unassigned,
        "note": (
            f"按工作目录归并了 {sessions_total} 个会话，得到 {len(projects)} 个项目；"
            f"其中 {unassigned} 个会话没有记录工作目录，未归入任何项目。"
            "大小与时间取自各 Agent 自己的记录，不完整时以 0 表示。"
        ),
    }


def group(
    sessions: list[dict],
    scores: dict | None = None,
    usage: dict | None = None,
) -> dict:
    """Group ``Session.to_dict()`` payloads by their project folder.

    Returns ``{"projects", "total_projects", "unassigned", "note"}``. Each
    project carries its agent list, session count, total size, activity window,
    protection counters and a *trimmed* session list (``extra`` is never
    included). Projects are sorted by total size, then by session count.

    ``scores`` maps ``"<agent>|<sid>"`` to a score dict (``score`` / ``tier``)
    and ``usage`` to a usage dict (``total_tokens``); both are optional and
    missing keys are tolerated everywhere.

    Never raises: on failure it returns a well-formed empty result.
    """
    try:
        items = [s for s in (sessions or []) if isinstance(s, dict)]
        sc_map = scores if isinstance(scores, dict) else {}
        us_map = usage if isinstance(usage, dict) else {}
    except Exception:
        return _empty("整理项目分组时出错，未生成任何结果。")

    buckets: dict[str, dict] = {}
    unassigned = 0
    total_sessions = 0

    for s in items:
        try:
            total_sessions += 1
            key = project_key(s.get("cwd") or "")
            if not key:
                unassigned += 1
                continue
            agent = str(s.get("agent") or "")
            sid = str(s.get("sid") or "")
            sc = _score_of(sc_map, agent, sid)
            tokens = _tokens_of(us_map, agent, sid)

            b = buckets.get(key)
            if b is None:
                b = {
                    "key": key,
                    "label": label(key),
                    "path": str(s.get("cwd") or ""),
                    "agents": set(),
                    "session_count": 0,
                    "total_bytes": 0,
                    "first_at": None,
                    "last_at": None,
                    "protected_count": 0,
                    "pinned_count": 0,
                    "junk_count": 0,
                    "score_sum": 0,
                    "score_n": 0,
                    "sessions": [],
                }
                buckets[key] = b
            elif not b["path"] and s.get("cwd"):
                # Prefer a real, cased path over a normalised key when the first
                # session in the bucket had none.
                b["path"] = str(s["cwd"])

            if agent:
                b["agents"].add(agent)
            b["session_count"] += 1
            try:
                size = int(s.get("size") or 0)
            except (TypeError, ValueError):
                size = 0
            b["total_bytes"] += size

            at = _activity(s)
            if at:
                if b["first_at"] is None or at < b["first_at"]:
                    b["first_at"] = at
                if b["last_at"] is None or at > b["last_at"]:
                    b["last_at"] = at

            if s.get("protected"):
                b["protected_count"] += 1
            if s.get("pinned"):
                b["pinned_count"] += 1
            tier = str(sc.get("tier") or "")
            if tier in JUNK_TIERS:
                b["junk_count"] += 1
            score = sc.get("score")
            if isinstance(score, (int, float)) and not isinstance(score, bool):
                b["score_sum"] += float(score)
                b["score_n"] += 1

            b["sessions"].append(_trim(s, sc, tokens))
        except Exception:
            # One malformed payload must not lose the rest of the report.
            continue

    projects: list[dict] = []
    for b in buckets.values():
        try:
            agents = sorted(b["agents"])
            first_at, last_at = b["first_at"], b["last_at"]
            projects.append(
                {
                    "key": b["key"],
                    "label": b["label"],
                    "path": b["path"],
                    "agents": agents,
                    "agent_count": len(agents),
                    "session_count": b["session_count"],
                    "total_bytes": b["total_bytes"],
                    "total_bytes_h": human_size(b["total_bytes"]),
                    "first_at": first_at,
                    "last_at": last_at,
                    "first_iso": ms_to_iso(first_at),
                    "last_iso": ms_to_iso(last_at),
                    "protected_count": b["protected_count"],
                    "pinned_count": b["pinned_count"],
                    "junk_count": b["junk_count"],
                    "score_avg": (
                        round(b["score_sum"] / b["score_n"], 1)
                        if b["score_n"]
                        else None
                    ),
                    "sessions": b["sessions"],
                }
            )
        except Exception:
            continue

    try:
        return _finish(projects, unassigned, total_sessions)
    except Exception:
        return _empty("整理项目分组时出错，未生成任何结果。")


def agents_for_path(path: str, sessions: list[dict]) -> list[str]:
    """Agent ids that have at least one session in this exact project key.

    Answers "who has worked in this folder?" for a click-through from a project
    row. Matching is on the normalised key, so a trailing separator, mixed
    separators or a different letter case still match. Never raises.
    """
    try:
        target = project_key(path)
        if not target:
            return []
        found: set[str] = set()
        for s in sessions or []:
            if not isinstance(s, dict):
                continue
            if project_key(s.get("cwd") or "") != target:
                continue
            agent = str(s.get("agent") or "")
            if agent:
                found.add(agent)
        return sorted(found)
    except Exception:
        return []
