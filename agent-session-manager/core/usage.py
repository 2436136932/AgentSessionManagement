"""Per-session usage accounting (tokens, cost, duration).

Two agents expose real numbers locally, in different shapes:

  * DSH     -- ~/.dsh/storages/session_projcache/sessions/<sid>.json holds
              `tokenUsage.totals` (uncachedInputTokens, outputTokens,
              cacheReadTokens, cacheWriteTokens) and `sessionStats`
              (turns, steps, llmMs, toolMs, ttftMs, decodeMs, decodeTokens).
  * CodeBuddy -- <conversation>/index.json holds a `requests` array, each with
              a `usage` object carrying inputTokens, outputTokens, cacheTokens,
              totalTokens and a `credit` cost figure.

  * Copilot / WorkBuddy / Antigravity -- no usage data is stored locally
              (verified: the Copilot schema has no token columns at all;
              WorkBuddy's session_usage table was empty and its columns are
              session/size shaped, not token shaped). These are reported as
              "not available" rather than shown as zero, so a zero is never
              mistaken for "this session was free".

Cost is only reported when the agent itself stores a currency figure
(CodeBuddy's `credit`). DSH records `cost: 0` in its usage ledger, which is not
a real price, so no monetary value is invented for it.
"""

from __future__ import annotations

from adapters.registry import all_adapters

#: Tokens are summed into these canonical buckets.
BUCKETS = ("input", "output", "cache_read", "cache_write", "total")


def _blank() -> dict:
    return {k: 0 for k in BUCKETS}


def _empty_session(agent: str, agent_label: str, sid: str, title: str) -> dict:
    return {
        "agent": agent,
        "agent_label": agent_label,
        "sid": sid,
        "title": title,
        "available": False,
        "reason": "",
        "tokens": _blank(),
        "cost": None,
        "cost_unit": "",
        "turns": None,
        "steps": None,
        "llm_ms": None,
        "tool_ms": None,
        "ttft_ms": None,
        "extra": {},
    }


def dsh_usage(adapter, sid: str) -> dict:
    """Read tokenUsage + sessionStats for one DSH session."""
    from core.util import read_json

    out = _empty_session(adapter.id, adapter.label, sid, "")
    rec = read_json(adapter.projcache_dir() / f"{sid}.json", None)
    if not isinstance(rec, dict):
        out["reason"] = "没有该会话的元数据缓存，无法读取用量。"
        return out
    rows = ((rec.get("record") or {}).get("rows")) or {}

    t = (rows.get("tokenUsage") or {}).get("val")
    if isinstance(t, dict) and isinstance(t.get("totals"), dict):
        tot = t["totals"]
        out["tokens"]["input"] = int(tot.get("uncachedInputTokens") or 0)
        out["tokens"]["output"] = int(tot.get("outputTokens") or 0)
        out["tokens"]["cache_read"] = int(tot.get("cacheReadTokens") or 0)
        out["tokens"]["cache_write"] = int(tot.get("cacheWriteTokens") or 0)
        out["tokens"]["total"] = sum(
            out["tokens"][k] for k in ("input", "output", "cache_read", "cache_write")
        )
        out["available"] = True

    st = (rows.get("sessionStats") or {}).get("val")
    if isinstance(st, dict):
        out["turns"] = st.get("turns")
        out["steps"] = st.get("steps")
        out["llm_ms"] = st.get("llmMs")
        out["tool_ms"] = st.get("toolMs")
        out["ttft_ms"] = st.get("ttftMs")
        out["extra"] = {
            "decode_ms": st.get("decodeMs"),
            "decode_tokens": st.get("decodeTokens"),
        }
        out["available"] = True

    # Surface an in-progress step: useful for spotting a session still running.
    if isinstance(st, dict) and st.get("openStep"):
        out["extra"]["running"] = True

    if not out["available"]:
        out["reason"] = "该会话没有记录用量信息（可能是空的幽灵条目）。"
    return out


def codebuddy_usage(adapter, sid: str) -> dict:
    """Aggregate the `usage` of every request in a CodeBuddy conversation."""
    import json

    from core.util import read_json

    out = _empty_session(adapter.id, adapter.label, sid, "")
    parts = adapter._split_sid(sid)
    if parts is None:
        out["reason"] = "无法解析会话 ID。"
        return out
    project, conv = parts

    conv_dir = None
    owner_ws = None
    for ws, proj in adapter._projects():
        if proj != project:
            continue
        cand = ws / "history" / project / conv
        if cand.is_dir():
            conv_dir, owner_ws = cand, ws
            break
    if conv_dir is None:
        out["reason"] = "找不到该会话目录（可能是残留索引）。"
        return out

    for c in adapter._read_project_index(owner_ws, project):
        if str(c.get("id")) == conv:
            out["title"] = str(c.get("name") or "")
            break

    idx = read_json(conv_dir / "index.json", {}) or {}
    reqs = idx.get("requests") if isinstance(idx, dict) else None
    if not isinstance(reqs, list) or not reqs:
        out["reason"] = "该会话没有 requests 记录，无法统计用量。"
        return out

    credit = 0.0
    saw_credit = False
    n = 0
    for r in reqs:
        if not isinstance(r, dict):
            continue
        u = r.get("usage")
        if not isinstance(u, dict):
            continue
        n += 1
        inp = int(u.get("inputTokens") or 0)
        out_t = int(u.get("outputTokens") or 0)
        cache = int(u.get("cacheTokens") or 0)
        # CodeBuddy lists cacheTokens separately from inputTokens; keep them
        # apart so the totals are not double counted.
        out["tokens"]["input"] += inp
        out["tokens"]["output"] += out_t
        out["tokens"]["cache_read"] += cache
        cr = u.get("credit")
        if isinstance(cr, (int, float)):
            credit += float(cr)
            saw_credit = True

    if n:
        out["tokens"]["total"] = (
            out["tokens"]["input"]
            + out["tokens"]["output"]
            + out["tokens"]["cache_read"]
            + out["tokens"]["cache_write"]
        )
        out["available"] = True
        out["turns"] = n
        out["extra"] = {
            "requests": n,
            "types": sorted({str(r.get("type")) for r in reqs if r.get("type")}),
        }
        if saw_credit:
            out["cost"] = round(credit, 4)
            out["cost_unit"] = "credit"
    else:
        out["reason"] = "requests 里没有 usage 字段。"
    return out


def for_session(agent_id: str, sid: str) -> dict:
    """Usage for one session, dispatched to the right adapter."""
    adapter = next((a for a in all_adapters() if a.id == agent_id), None)
    if adapter is None:
        return _empty_session(agent_id, agent_id, sid, "")

    if agent_id == "dsh":
        return dsh_usage(adapter, sid)
    if agent_id == "codebuddy":
        return codebuddy_usage(adapter, sid)

    out = _empty_session(adapter.id, adapter.label, sid, "")
    out["reason"] = (
        f"{adapter.label} 在本机不保存 token 用量或费用数据，因此无法统计。"
    )
    return out


def summary() -> dict:
    """Usage across every session, plus which agents can report it at all."""
    per_agent: dict[str, dict] = {}
    sessions: list[dict] = []
    total = _blank()
    total_cost = 0.0
    cost_agents: set[str] = set()

    for a in all_adapters():
        try:
            if not a.detect():
                continue
            listing = a.list_sessions()
        except Exception:
            continue
        for s in listing:
            u = for_session(a.id, s.sid)
            d = {
                "agent": a.id,
                "agent_label": a.label,
                "sid": s.sid,
                "title": s.title,
                "size": s.size,
                **{k: u[k] for k in ("available", "reason", "tokens", "cost",
                                     "cost_unit", "turns", "steps", "llm_ms",
                                     "tool_ms", "ttft_ms", "extra")},
            }
            sessions.append(d)
            e = per_agent.setdefault(
                a.id,
                {"agent": a.id, "label": a.label, "sessions": 0,
                 "with_usage": 0, "tokens": _blank(), "cost": None,
                 "cost_unit": "", "reason": ""},
            )
            e["sessions"] += 1
            if u["available"]:
                e["with_usage"] += 1
                for k in BUCKETS:
                    e["tokens"][k] += u["tokens"][k]
                if u["cost"] is not None:
                    e["cost"] = (e["cost"] or 0.0) + u["cost"]
                    e["cost_unit"] = u["cost_unit"]
                    cost_agents.add(a.id)
                for k in BUCKETS:
                    total[k] += u["tokens"][k]
                if u["cost"] is not None:
                    total_cost += u["cost"]
            elif not e["reason"]:
                e["reason"] = u["reason"]

    return {
        "agents": sorted(per_agent.values(), key=lambda x: x["agent"]),
        "sessions": sorted(sessions, key=lambda x: -(x["tokens"]["total"] or 0)),
        "totals": total,
        "total_cost": round(total_cost, 4) if cost_agents else None,
        "cost_agents": sorted(cost_agents),
    }
