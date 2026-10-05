"""Retention rules: propose sessions to clean up, never delete them.

The value of a rule here is *discovery*, not automation. A rule turns "I have
18 sessions and don't know which are junk" into a short, reviewable list with a
stated reason per item. Every proposal carries the reason it matched, and
nothing is ever executed by this module -- the caller decides.

Rules implemented (all opt-in, all parameterised):

  blank      -- sessions with no messages at all (an empty shell)
  ghost      -- index entry whose content is gone (DSH/VSCode residue)
  orphan     -- content not referenced by any workspace index
  old        -- last activity older than N days
  small      -- below a size threshold AND older than N days (trivially
                recreatable scratch sessions)
  oversized  -- larger than N MB (usually worth reviewing by hand)
  unread     -- never opened since creation, older than N days

A rule never proposes a pinned session; those are filtered out and counted
separately so the user can see the protection working.
"""

from __future__ import annotations

from core.util import now_ms

DAY_MS = 86_400_000

#: Rule weights for the value score, and the signals it reads.
#: The score answers "is this session worth keeping?" using only facts already
#: on disk -- it never guesses. Signals are deliberately few and legible so a
#: user can see *why* a session scored as it did.
SCORE_SIGNALS = {
    "turns": {"label": "对话轮次", "weight": 3},
    "tokens": {"label": "token 投入", "weight": 3},
    "content": {"label": "内容体量", "weight": 2},
    "tools": {"label": "工具调用", "weight": 1},
    "size": {"label": "磁盘占用", "weight": 1},
}

#: Value tiers, from most to least worth keeping.
TIERS = [
    (70, "high", "值得保留", "内容与投入都较多，建议保留"),
    (40, "medium", "可以保留", "有一定内容，删除前建议看一眼"),
    (15, "low", "价值较低", "内容很少，通常是试探性对话"),
    (0, "junk", "基本无价值", "几乎是空会话或残留，可安全清理"),
]


def _tier(score: int) -> tuple[str, str, str]:
    for floor, key, label, why in TIERS:
        if score >= floor:
            return key, label, why
    return "junk", "基本无价值", "几乎是空会话或残留，可安全清理"


def score_session(s: dict, usage: dict | None = None,
                  message_count: int | None = None,
                  preview: dict | None = None) -> dict:
    """Estimate how valuable a session looks, 0-100.

    Each signal is normalised against a soft ceiling (a session at or above the
    ceiling gets full marks) and weighted. The result is advisory: it exists to
    put the obviously-empty sessions at one end and the heavily-used ones at
    the other, so a bulk decision is not made blind.
    """
    signals: list[dict] = []
    total = 0.0
    max_total = sum(v["weight"] for v in SCORE_SIGNALS.values())

    def add(name: str, raw: float, ceiling: float):
        nonlocal total
        w = SCORE_SIGNALS[name]["weight"]
        ratio = 0.0 if ceiling <= 0 else min(1.0, max(0.0, raw / ceiling))
        pts = ratio * w
        total += pts
        signals.append(
            {
                "name": name,
                "label": SCORE_SIGNALS[name]["label"],
                "raw": raw,
                "ceiling": ceiling,
                "points": round(pts, 2),
                "weight": w,
            }
        )

    # A ghost has no content at all: the strongest possible "junk" signal.
    if s.get("is_ghost"):
        return {
            "score": 0,
            "tier": "junk",
            "tier_label": "基本无价值",
            "tier_why": "残留索引，正文已不存在",
            "signals": [],
            "certainty": "confirmed",
        }

    u = usage or {}
    turns = (u.get("turns") or 0)
    tokens = ((u.get("tokens") or {}).get("total") or 0)
    msgs = message_count if message_count is not None else 0

    add("turns", float(turns), 20.0)
    add("tokens", float(tokens), 5_000_000.0)
    add("content", float(msgs), 200.0)
    add("tools", float(u.get("tool_calls") or 0), 50.0)
    add("size", float(s.get("size") or 0), 2_000_000.0)

    score = int(round(100 * total / max_total)) if max_total else 0
    # An orphan/ghost is suspect regardless of score.
    if s.get("is_orphan") and score > 0:
        score = max(0, score - 10)

    key, label, why = _tier(score)

    # Honesty guard: a session can score 0 simply because its content is not on
    # this machine (WorkBuddy keeps transcripts cloud-side). Reporting that as
    # "worthless" would invite deleting something valuable, so it is labelled
    # low-confidence instead.
    #
    # The adapter is the authority here: its preview reports
    # extra.has_local_content=false when the body genuinely is not local, and
    # that must not be confused with "the session is empty".
    certainty = "confirmed"
    extra = preview.get("extra") if isinstance(preview, dict) else None
    declared_local = None
    if isinstance(extra, dict) and "has_local_content" in extra:
        declared_local = bool(extra["has_local_content"])

    if score <= 15:
        if declared_local is False:
            certainty = "unknown"
        elif not (tokens or turns or msgs):
            certainty = "unknown"

    if certainty == "unknown":
        label = "无法评估"
        why = (
            "本机没有该会话的内容或用量数据"
            "（正文可能保存在云端），因此无法判断价值，请勿仅凭此分数删除。"
        )
        key = "unknown"

    return {
        "score": score,
        "tier": key,
        "tier_label": label,
        "tier_why": why,
        "signals": signals,
        "certainty": certainty,
    }


def score_all(sessions: list[dict], usage_by_key: dict | None = None,
              previews: dict | None = None) -> dict[str, dict]:
    """Score every session, keyed by '<agent>|<sid>'."""
    usage_by_key = usage_by_key or {}
    previews = previews or {}
    out: dict[str, dict] = {}
    for s in sessions:
        key = f"{s.get('agent','')}|{s.get('sid','')}"
        u = usage_by_key.get(key)
        p = previews.get(key)
        mc = p.get("total_messages") if isinstance(p, dict) else None
        out[key] = score_session(s, u, mc, p)
    return out
RULES: dict[str, dict] = {
    "blank": {"label": "空会话", "detail": "没有任何消息内容"},
    "ghost": {"label": "幽灵条目", "detail": "索引存在但正文已丢失"},
    "orphan": {"label": "孤儿会话", "detail": "不在任何工作区索引中"},
    "old": {"label": "长期未用", "params": ["days"], "detail": "超过指定天数未活动"},
    "small": {"label": "零碎小会话", "params": ["days", "max_kb"], "detail": "体积很小且久未使用"},
    "oversized": {"label": "体积过大", "params": ["min_mb"], "detail": "占用空间较大，建议人工查看"},
    "unread": {"label": "从未打开", "params": ["days"], "detail": "创建后从未真正使用"},
}


def _blank_cache():
    return {}


def evaluate(
    sessions: list[dict],
    previews: dict[str, dict] | None = None,
    rules: list[str] | None = None,
    days: int = 30,
    max_kb: int = 20,
    min_mb: int = 5,
) -> dict:
    """Apply the selected rules.

    `sessions` are Session.to_dict() payloads. `previews` maps "<agent>|<sid>"
    to a preview payload; it is optional and only needed for the `blank` rule
    (which must actually look at the content rather than trust a size).
    """
    active = rules if rules else ["ghost", "orphan", "blank", "old"]
    active = [r for r in active if r in RULES]
    previews = previews or {}
    cutoff = now_ms() - days * DAY_MS

    proposals: list[dict] = []
    skipped_pinned: list[dict] = []

    for s in sessions:
        agent, sid = s.get("agent", ""), s.get("sid", "")
        key = f"{agent}|{sid}"
        reasons: list[str] = []

        if "ghost" in active and s.get("is_ghost"):
            reasons.append("幽灵条目：索引存在但正文已丢失")
        if "orphan" in active and s.get("is_orphan"):
            reasons.append("孤儿会话：不在任何工作区索引中")

        if "blank" in active:
            p = previews.get(key)
            if isinstance(p, dict) and p.get("available") and not p.get("messages"):
                reasons.append("空会话：没有任何消息内容")

        upd = s.get("updated_at") or s.get("created_at") or 0
        if "old" in active and upd and upd < cutoff:
            reasons.append(f"长期未用：最后活动超过 {days} 天")
        if "small" in active and upd and upd < cutoff:
            # Only when it is content-free or tiny; avoids proposing a small
            # but important session.
            if 0 < (s.get("size") or 0) < max_kb * 1024:
                reasons.append(f"零碎小会话：{max_kb} KB 以下且超过 {days} 天未用")
        if "oversized" in active and (s.get("size") or 0) >= min_mb * 1024 * 1024:
            reasons.append(f"体积过大：超过 {min_mb} MB")
        if "unread" in active and upd and upd < cutoff:
            created = s.get("created_at") or 0
            if created and s.get("updated_at") == created:
                reasons.append(f"从未打开：创建后 {days} 天未再活动")

        if not reasons:
            continue

        item = {
            "agent": agent,
            "agent_label": s.get("agent_label", ""),
            "sid": sid,
            "title": s.get("title", ""),
            "size": s.get("size", 0),
            "updated_at": upd,
            "updated_iso": s.get("updated_iso", ""),
            "is_ghost": s.get("is_ghost", False),
            "is_orphan": s.get("is_orphan", False),
            "reasons": reasons,
            "rule_count": len(reasons),
        }
        if s.get("protected"):
            item["skipped"] = (
                "已标记保留，已跳过"
                if s.get("pinned")
                else f"所在工作区已标记保留（{s.get('workspace_pin_path', '')}），已跳过"
            )
            skipped_pinned.append(item)
        else:
            proposals.append(item)

    # Most reasons first, then oldest: the strongest candidates surface first.
    proposals.sort(key=lambda x: (-x["rule_count"], x["updated_at"] or 0))

    by_rule: dict[str, int] = {}
    for p in proposals:
        for r in p["reasons"]:
            name = r.split("：")[0]
            by_rule[name] = by_rule.get(name, 0) + 1

    return {
        "active_rules": active,
        "params": {"days": days, "max_kb": max_kb, "min_mb": min_mb},
        "proposals": proposals,
        "proposal_count": len(proposals),
        "proposal_bytes": sum(p["size"] or 0 for p in proposals),
        "skipped_pinned": skipped_pinned,
        "skipped_count": len(skipped_pinned),
        "by_rule": by_rule,
        "rule_catalog": {k: RULES[k] for k in RULES},
        "note": "本页只做建议，不会删除任何数据。请在「会话」页确认后再操作。",
    }
