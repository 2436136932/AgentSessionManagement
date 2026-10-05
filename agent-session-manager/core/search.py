"""Full-text search across session *content*, not just titles.

Why this needs its own reader rather than reusing preview(): preview() clips
messages (3000 chars each, 400 messages max) so a large session can hide a
match. Search therefore walks the raw store and extracts plain text itself.

Cost is acceptable at this scale: a full sweep of every session on a real
machine (18 sessions, ~1836 messages, ~16 MB decompressed) takes about a
second. Results are cached in memory and invalidated whenever a delete
happens, exactly like inventory.scan().

Every adapter exposes an optional `iter_text(sid)` generator yielding
(role, kind, text) triples. Adapters that cannot read content simply yield
nothing and are reported as non-searchable rather than silently empty.
"""

from __future__ import annotations

import re
import threading
import time

from adapters.registry import all_adapters

#: A search index entry: one match with surrounding context.
_LOCK = threading.RLock()
_CACHE: dict = {"at": 0.0, "docs": []}
_TTL = 120.0

#: How much context to return around a match.
CONTEXT_BEFORE = 90
CONTEXT_AFTER = 140

#: Maximum matches returned per query overall.
MAX_MATCHES_PER_QUERY = 300
#: Maximum matches returned per session.
MAX_MATCHES_PER_SESSION = 12


def invalidate() -> None:
    with _LOCK:
        _CACHE["at"] = 0.0
        _CACHE["docs"] = []


def _build_docs() -> list[dict]:
    """Collect searchable text from every installed adapter."""
    docs: list[dict] = []
    for a in all_adapters():
        try:
            if not a.detect():
                continue
        except Exception:
            continue
        try:
            sessions = a.list_sessions()
        except Exception:
            continue
        for s in sessions:
            chunks: list[tuple[str, str, str]] = []
            try:
                it = getattr(a, "iter_text", None)
                if callable(it):
                    for role, kind, text in it(s.sid):
                        if text:
                            chunks.append((role, kind, text))
            except Exception:
                chunks = []
            docs.append(
                {
                    "agent": a.id,
                    "agent_label": a.label,
                    "sid": s.sid,
                    "title": s.title,
                    "cwd": s.cwd,
                    "updated_at": s.updated_at,
                    "size": s.size,
                    "is_ghost": s.is_ghost,
                    "is_orphan": s.is_orphan,
                    "searchable": bool(chunks),
                    "chunks": chunks,
                }
            )
    return docs


def docs(force: bool = False) -> list[dict]:
    with _LOCK:
        if not force and _CACHE["docs"] and (time.time() - _CACHE["at"]) < _TTL:
            return _CACHE["docs"]
    built = _build_docs()
    with _LOCK:
        _CACHE["docs"] = built
        _CACHE["at"] = time.time()
    return built


def _snippet(text: str, start: int, end: int) -> str:
    a = max(0, start - CONTEXT_BEFORE)
    b = min(len(text), end + CONTEXT_AFTER)
    pre = "…" if a > 0 else ""
    post = "…" if b < len(text) else ""
    return f"{pre}{text[a:b]}{post}".replace("\n", " ").strip()


def search(
    query: str,
    agent: str = "",
    case_sensitive: bool = False,
    regex: bool = False,
    limit: int = MAX_MATCHES_PER_QUERY,
) -> dict:
    """Search session content.

    Returns per-session results with snippets, plus a summary of which agents
    were searchable (so an empty result is never mistaken for "no content").
    """
    q = (query or "").strip()
    out = {
        "query": q,
        "regex": regex,
        "case_sensitive": case_sensitive,
        "results": [],
        "total_matches": 0,
        "searched_sessions": 0,
        "unsearchable_sessions": 0,
        "agents_searchable": [],
        "agents_unsearchable": [],
        "truncated": False,
        "elapsed_ms": 0,
    }
    if not q:
        return out

    t0 = time.time()
    pattern = None
    if regex:
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            pattern = re.compile(q, flags)
        except re.error as e:
            out["error"] = f"正则表达式无效：{e}"
            return out
    needle = q if case_sensitive else q.lower()

    all_docs = docs()
    searchable_agents: set[str] = set()
    unsearchable_agents: set[str] = set()
    total = 0

    for d in all_docs:
        if agent and d["agent"] != agent:
            continue
        if not d["searchable"]:
            out["unsearchable_sessions"] += 1
            unsearchable_agents.add(d["agent"])
            continue
        out["searched_sessions"] += 1
        searchable_agents.add(d["agent"])

        hits: list[dict] = []
        for role, kind, text in d["chunks"]:
            if not text:
                continue
            hay = text if case_sensitive else text.lower()
            if pattern is not None:
                spans = [(m.start(), m.end()) for m in pattern.finditer(text)]
            else:
                spans = []
                # Plain substring search, but report the first N occurrences.
                pos = hay.find(needle)
                while pos != -1 and len(spans) < MAX_MATCHES_PER_SESSION:
                    spans.append((pos, pos + len(needle)))
                    pos = hay.find(needle, pos + max(1, len(needle)))
            for start, end in spans:
                if len(hits) >= MAX_MATCHES_PER_SESSION:
                    break
                hits.append(
                    {
                        "role": role,
                        "kind": kind,
                        "snippet": _snippet(text, start, end),
                    }
                )
            if len(hits) >= MAX_MATCHES_PER_SESSION:
                break

        if hits:
            total += len(hits)
            out["results"].append(
                {
                    "agent": d["agent"],
                    "agent_label": d["agent_label"],
                    "sid": d["sid"],
                    "title": d["title"],
                    "cwd": d["cwd"],
                    "updated_at": d["updated_at"],
                    "size": d["size"],
                    "is_ghost": d["is_ghost"],
                    "is_orphan": d["is_orphan"],
                    "match_count": len(hits),
                    "matches": hits,
                }
            )

    # Most recent sessions first: a match in a session you used yesterday is
    # far more likely to be the one you meant.
    out["results"].sort(key=lambda r: -(r.get("updated_at") or 0))
    if len(out["results"]) > limit:
        out["results"] = out["results"][:limit]
        out["truncated"] = True

    out["total_matches"] = total
    out["agents_searchable"] = sorted(searchable_agents)
    out["agents_unsearchable"] = sorted(unsearchable_agents)
    out["elapsed_ms"] = int((time.time() - t0) * 1000)
    return out


def stats() -> dict:
    """What content is available to search, per agent."""
    ds = docs()
    per: dict[str, dict] = {}
    for d in ds:
        e = per.setdefault(
            d["agent"],
            {"agent": d["agent"], "label": d["agent_label"],
             "sessions": 0, "searchable": 0, "chars": 0, "messages": 0},
        )
        e["sessions"] += 1
        if d["searchable"]:
            e["searchable"] += 1
            e["messages"] += len(d["chunks"])
            e["chars"] += sum(len(c[2]) for c in d["chunks"])
    return {
        "agents": sorted(per.values(), key=lambda x: x["agent"]),
        "total_sessions": len(ds),
        "total_searchable": sum(1 for d in ds if d["searchable"]),
        "total_chars": sum(sum(len(c[2]) for c in d["chunks"]) for d in ds),
    }
