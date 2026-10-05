"""Read-only credential scan over session transcripts.

Purpose: answer "what is actually inside this conversation?" *before* it is
deleted or exported. A session can hold an API key pasted into a prompt, a
password echoed by a shell command, or a connection string caught in a config
dump. Once the session is gone there is no way to learn what left with it.

THIS MODULE IS STRICTLY READ-ONLY. It opens files for reading and walks the
adapters' ``iter_text()`` generators; it never deletes, quarantines, rewrites
or otherwise touches a single byte of session data. It reports, and the caller
decides.

Three rules shape the implementation:

  * **A secret is never returned in the clear.** Every hit carries a preview
    produced by :func:`mask`, and there is no code path that hands back the raw
    match -- including for a session the caller asked about by mistake.
  * **"Cannot look" is not "clean".** When an adapter has no readable body on
    this machine (WorkBuddy keeps transcripts cloud-side), the result says so
    in Chinese rather than reporting zero hits, because 0 findings and 0
    readability are very different answers to "is it safe to delete this?".
  * **No regex may blow up.** Every pattern is a flat character-class run with
    bounded quantifiers -- no nested quantifiers, no ambiguous alternatives --
    and each session's scan is capped at 8 MiB of text.
"""

from __future__ import annotations

import re
from pathlib import Path

# --------------------------------------------------------------------------
# Limits
# --------------------------------------------------------------------------

#: Hard cap on how much text one session (or one file) contributes to a scan.
#: This is the guard that keeps a crafted 1 GB transcript from turning a
#: credentials report into a denial of service.
MAX_SCAN_CHARS = 8 * 1024 * 1024

#: A masked preview is capped at this many characters.
PREVIEW_MAX = 80

#: Characters kept at each end of a masked secret.
MASK_KEEP = 4

#: Severity ordering, most serious first.
SEVERITIES = ("high", "medium", "low")

_SEV_RANK = {"high": 3, "medium": 2, "low": 1}

#: How many raw matches are collected before the scan stops looking. Bounded so
#: a pathological input (a file of nothing but `password=`) cannot make this
#: module allocate without limit.
_MIN_COLLECT = 400

#: Kinds that carry only bookkeeping metadata, never conversation prose. An
#: adapter that yields nothing but these has no readable body on this machine,
#: so its scan must be reported as unavailable rather than as "clean".
METADATA_KINDS = frozenset(
    {
        "title", "cwd", "model", "expert_id", "mode", "group_title",
        "source_mode", "status", "visibility", "sandbox", "transport",
    }
)


# --------------------------------------------------------------------------
# Patterns
# --------------------------------------------------------------------------
# Each entry: {"id", "label" (Chinese), "regex" (compiled), "severity"}.
# Severity is about "how usable is this to an attacker", not about how often it
# appears: a provider-shaped key is `high`, a value that only *looks* like a
# credential without its context is `medium` or `low`.
#
# Backtracking review, pattern by pattern: every one of them is a sequence of
# single-character classes joined by simple bounded quantifiers or `?:`
# alternation of literals. None nests a quantifier inside a quantified group,
# and none can match the same character two different ways, so each runs in
# linear time over the input.

PATTERNS: list[dict] = [
    {
        "id": "openai-key",
        "label": "OpenAI API 密钥",
        "regex": re.compile(r"\bsk-(?!ant-)[A-Za-z0-9_\-]{20,}"),
        "severity": "high",
    },
    {
        "id": "anthropic-key",
        "label": "Anthropic API 密钥",
        "regex": re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{8,}"),
        "severity": "high",
    },
    {
        "id": "github-token",
        "label": "GitHub 令牌",
        "regex": re.compile(
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,}\b"
            r"|\bgithub_pat_[A-Za-z0-9_]{20,}\b"
        ),
        "severity": "high",
    },
    {
        "id": "aws-access-key-id",
        "label": "AWS 访问密钥 ID",
        "regex": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "severity": "high",
    },
    {
        # Context-dependent by nature: 40 base64-ish characters are only an AWS
        # secret when the label next to them says so. Kept at `medium`.
        "id": "aws-secret-access-key",
        "label": "AWS 私有访问密钥（依赖上下文判断）",
        "regex": re.compile(
            r"(?i)(?:aws[_\-\s]?)?(?:secret[_\-\s]?)?access[_\-\s]?key"
            r"\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{40}"
        ),
        "severity": "medium",
    },
    {
        "id": "google-api-key",
        "label": "Google API 密钥",
        "regex": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        "severity": "high",
    },
    {
        "id": "slack-token",
        "label": "Slack 令牌",
        "regex": re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}"),
        "severity": "high",
    },
    {
        "id": "stripe-key",
        "label": "Stripe 生产密钥",
        "regex": re.compile(r"\b(?:sk_live_|rk_live_)[0-9A-Za-z]{16,}"),
        "severity": "high",
    },
    {
        "id": "bearer-token",
        "label": "Bearer 令牌",
        "regex": re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]{20,}={0,2}"),
        "severity": "medium",
    },
    {
        "id": "pem-private-key",
        "label": "PEM 私钥文件头",
        "regex": re.compile(r"-{5}BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-{5}"),
        "severity": "high",
    },
    {
        "id": "jwt",
        "label": "JWT 令牌",
        "regex": re.compile(
            r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}"
        ),
        "severity": "medium",
    },
    {
        "id": "assignment-secret",
        "label": "密码/密钥/令牌赋值",
        "regex": re.compile(
            r"(?i)\b(?:password|passwd|pwd|api[_\-\s]?key|apikey|secret[_\-\s]?key"
            r"|access[_\-\s]?token|auth[_\-\s]?token|token|secret)"
            r"\s*[:=]\s*[\"']?[^\s\"',;]{6,200}"
        ),
        "severity": "medium",
    },
    {
        "id": "weak-password-assignment",
        "label": "较短的密码赋值（弱信号）",
        "regex": re.compile(
            r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*[\"']?"
            r"[^\s\"',;]{1,5}(?![^\s\"',;])"
        ),
        "severity": "low",
    },
    {
        "id": "cn-credential",
        "label": "中文语境下的密码/密钥/令牌",
        "regex": re.compile(
            r"(?:密码|密钥|口令|令牌|私钥|凭据|访问密钥|密钥串)"
            r"\s*[:：=＝]\s*[\"']?[^\s\"',;，。；、]{4,200}"
        ),
        "severity": "medium",
    },
    {
        "id": "connection-string",
        "label": "带账号密码的连接串",
        "regex": re.compile(
            r"(?i)\b[a-z][a-z0-9+.\-]{1,15}://[^\s:/@]{1,64}:[^\s:/@]{3,128}"
            r"@[^\s/]{1,200}"
        ),
        "severity": "high",
    },
    {
        "id": "ipv4-credential",
        "label": "IP 地址前的账号:密码",
        "regex": re.compile(
            r"\b[A-Za-z0-9._%+\-]{1,64}:[^\s:@/]{4,128}@(?:\d{1,3}\.){3}\d{1,3}\b"
        ),
        "severity": "medium",
    },
]


# --------------------------------------------------------------------------
# Masking
# --------------------------------------------------------------------------


def mask(text: str, keep: int = MASK_KEEP) -> str:
    """Hide the middle of a secret so a report can name it without leaking it.

    At most ``keep`` characters survive at each end. Anything short enough that
    two ends would meet (``len <= keep * 2``) keeps only its first character,
    so a 6-character password never comes back with 4 of its characters intact.
    """
    try:
        s = "" if text is None else str(text)
        if not s:
            return ""
        n = len(s)
        try:
            k = int(keep)
        except (TypeError, ValueError):
            k = MASK_KEEP
        if k < 0:
            k = 0
        if k == 0 or n <= k * 2:
            return s[0] + "*" * (n - 1)
        return s[:k] + "*" * (n - (k * 2)) + s[-k:]
    except Exception:
        # Never return the input on failure: masking must fail closed.
        return "***"


def _norm_sev(value) -> str:
    v = str(value or "").strip().lower()
    return v if v in _SEV_RANK else "low"


def _overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    """True when two spans share more than half of the shorter one."""
    s1, e1 = a
    s2, e2 = b
    inter = min(e1, e2) - max(s1, s2)
    if inter <= 0:
        return False
    shorter = min(e1 - s1, e2 - s2)
    return shorter > 0 and inter * 2 > shorter


def _scan(text: str, limit: int) -> tuple[list[dict], bool]:
    """Core scan: (hits, more_available). Internal; still masks everything."""
    if limit <= 0 or not isinstance(text, str) or not text:
        return [], False

    body = text[:MAX_SCAN_CHARS]
    clipped = len(text) > len(body)
    cap = max(_MIN_COLLECT, limit * 20)

    collected: list[tuple[int, int, dict]] = []
    capped = False
    for pat in PATTERNS:
        rx = pat.get("regex")
        if rx is None:
            continue
        try:
            for m in rx.finditer(body):
                try:
                    s, e = m.start(), m.end()
                except Exception:
                    continue
                if e <= s:
                    continue
                collected.append((s, e, pat))
                if len(collected) >= cap:
                    capped = True
                    break
        except Exception:
            # A pattern that misbehaves on one input must not sink the scan.
            continue
        if capped:
            break

    # Overlap resolution: when two hits share more than half of the shorter
    # one, only the more serious (then longer, then earlier) hit survives. This
    # is what stops `sk-ant-...` being reported once as OpenAI and once as
    # Anthropic, and what keeps a generic `token=` from shadowing the specific
    # pattern that actually identified the credential.
    ranked = sorted(
        collected,
        key=lambda x: (
            -_SEV_RANK.get(_norm_sev(x[2].get("severity")), 1),
            -(x[1] - x[0]),
            x[0],
        ),
    )
    kept: list[tuple[int, int, dict]] = []
    for item in ranked:
        span = (item[0], item[1])
        if any(_overlaps(span, (k[0], k[1])) for k in kept):
            continue
        kept.append(item)

    kept.sort(key=lambda x: (x[0], x[1]))
    more = capped or clipped or len(kept) > limit

    hits: list[dict] = []
    for s, e, pat in kept[:limit]:
        try:
            preview = mask(body[s:e])[:PREVIEW_MAX]
        except Exception:
            preview = "***"
        hits.append(
            {
                "pattern_id": str(pat.get("id") or ""),
                "label": str(pat.get("label") or ""),
                "severity": _norm_sev(pat.get("severity")),
                "preview": preview,
                "offset": int(s),
                "length": int(e - s),
            }
        )
    return hits, more


def scan_text(text: str, max_hits: int = 50) -> list[dict]:
    """Every credential-shaped hit in one piece of text.

    Returns ``{"pattern_id", "label", "severity", "preview", "offset",
    "length"}`` records with the secret masked in ``preview``. ``offset`` is
    relative to ``text`` (which is itself capped at 8 MiB). Never raises: on any
    failure it returns an empty list, and it never returns an unmasked match.
    """
    try:
        hits, _more = _scan(text, int(max_hits))
        return hits
    except Exception:
        return []


def scan_file(
    path: str | Path,
    max_bytes: int = MAX_SCAN_CHARS,
    max_hits: int = 50,
) -> list[dict]:
    """Scan a text file, reading at most ``max_bytes`` from its start.

    A file larger than the cap is reported on for its first ``max_bytes`` only
    -- reading a multi-gigabyte log in full is not worth the wait. Decoding uses
    ``errors="replace"`` so a binary-flavoured file is scanned rather than
    rejected. Missing, locked or unreadable files return an empty list.
    """
    try:
        cap = max(1, int(max_bytes))
        with open(Path(path), "rb") as fh:
            raw = fh.read(cap)
    except (OSError, ValueError, TypeError):
        return []
    except Exception:
        return []
    try:
        text = raw.decode("utf-8", "replace")
    except Exception:
        return []
    return scan_text(text, max_hits)


# --------------------------------------------------------------------------
# Sessions
# --------------------------------------------------------------------------


def _empty_result(agent_id: str, sid: str) -> dict:
    return {
        "agent": str(agent_id or ""),
        "sid": str(sid or ""),
        "available": False,
        "reason": "",
        "hits": [],
        "counts": {s: 0 for s in SEVERITIES},
        "total": 0,
        "truncated": False,
    }


def _counts(hits: list[dict]) -> dict:
    out = {s: 0 for s in SEVERITIES}
    for h in hits:
        sev = _norm_sev(h.get("severity"))
        out[sev] = out.get(sev, 0) + 1
    return out


def _adapter(agent_id: str):
    from adapters.registry import get_adapter

    return get_adapter(agent_id)


def scan_session(agent_id: str, sid: str, max_hits: int = 50) -> dict:
    """Scan one session's raw, *unclipped* text for credentials.

    Uses the adapter's ``iter_text(sid)`` generator rather than a preview:
    previews clip long messages and cap how many they return, which is exactly
    where a pasted key tends to hide. Read at most 8 MiB of text per session.

    ``available`` is False -- with a Chinese ``reason`` -- whenever the content
    could not be read on this machine (no adapter, no body, or metadata only).
    Such a session is *not* reported as clean: a caller must not treat
    "0 hits, unavailable" as "nothing to worry about".

    Each hit's ``offset`` is relative to the piece of text (one message) that
    produced it, which is how it can be pointed at in the preview reader.
    """
    out = _empty_result(agent_id, sid)
    try:
        limit = int(max_hits)
    except (TypeError, ValueError):
        limit = 50
    if limit <= 0:
        return out

    try:
        adapter = _adapter(agent_id)
    except Exception:
        out["reason"] = "无法加载该 Agent 的适配器，未能扫描。"
        return out
    if adapter is None:
        out["reason"] = "本机没有安装该 Agent，无法读取会话正文。"
        return out

    walker = getattr(adapter, "iter_text", None)
    if not callable(walker):
        out["reason"] = "该 Agent 的适配器不支持读取会话正文，无法扫描。"
        return out

    hits: list[dict] = []
    used = 0
    saw_body = False
    saw_any = False
    truncated = False

    try:
        stream = walker(sid)
    except Exception:
        out["reason"] = "读取该会话正文时出错，未能扫描。"
        return out

    try:
        for chunk in stream:
            try:
                _role, kind, text = chunk
            except Exception:
                continue
            if not text or not isinstance(text, str):
                continue
            saw_any = True
            if str(kind or "") not in METADATA_KINDS:
                saw_body = True

            if used >= MAX_SCAN_CHARS:
                truncated = True
                break
            room = MAX_SCAN_CHARS - used
            piece = text if len(text) <= room else text[:room]
            used += len(piece)
            if len(piece) < len(text):
                truncated = True

            remaining = limit - len(hits)
            if remaining <= 0:
                truncated = True
                break
            found, more = _scan(piece, remaining)
            if found:
                hits.extend(found)
            if more:
                truncated = True
    except Exception:
        # Keep whatever was already read; a mid-stream failure is not a reason
        # to report the session as clean.
        truncated = True

    if len(hits) >= limit:
        truncated = True

    out["hits"] = hits
    out["counts"] = _counts(hits)
    out["total"] = len(hits)
    out["truncated"] = bool(truncated)

    if saw_body:
        out["available"] = True
    elif saw_any:
        out["reason"] = (
            "本机只有该会话的元数据（标题、目录、模型等），正文不在本机"
            "（例如保存在云端），因此无法确认其中是否含有密钥。"
        )
    else:
        out["reason"] = (
            "本机读不到该会话的任何文本：正文可能不在本机，"
            "或该会话本身没有内容。不能据此认为它“干净”。"
        )
    return out


def scan_sessions(sessions: list[dict], max_hits: int = 30) -> dict:
    """Scan many ``Session.to_dict()`` payloads; return only the ones that hit.

    Sessions with nothing found are counted, not listed -- a bulk report is
    read for its exceptions. Unavailable sessions are counted separately, so
    the reader can see how much of the list was never actually inspected.
    """
    results: list[dict] = []
    scanned = 0
    unavailable = 0
    by_severity = {s: 0 for s in SEVERITIES}
    total_sessions = 0

    try:
        for s in sessions or []:
            if not isinstance(s, dict):
                continue
            total_sessions += 1
            agent = str(s.get("agent") or "")
            sid = str(s.get("sid") or "")
            try:
                r = scan_session(agent, sid, max_hits=max_hits)
            except Exception:
                r = _empty_result(agent, sid)
                r["reason"] = "扫描该会话时出错。"
            if r.get("available"):
                scanned += 1
            else:
                unavailable += 1
            for sev, n in (r.get("counts") or {}).items():
                if sev in by_severity:
                    by_severity[sev] += int(n or 0)
            if r.get("total"):
                results.append(
                    {
                        "agent": agent,
                        "agent_label": str(s.get("agent_label") or ""),
                        "sid": sid,
                        "title": str(s.get("title") or ""),
                        "updated_at": s.get("updated_at"),
                        "updated_iso": str(s.get("updated_iso") or ""),
                        "available": bool(r.get("available")),
                        "reason": str(r.get("reason") or ""),
                        "hits": list(r.get("hits") or []),
                        "counts": dict(r.get("counts") or {}),
                        "total": int(r.get("total") or 0),
                        "truncated": bool(r.get("truncated")),
                    }
                )
    except Exception:
        pass

    results.sort(
        key=lambda x: (
            -int((x.get("counts") or {}).get("high", 0)),
            -int(x.get("total") or 0),
            -int(x.get("updated_at") or 0),
        )
    )
    total_hits = sum(int(x.get("total") or 0) for x in results)

    note = (
        f"共检查 {total_sessions} 个会话，其中 {scanned} 个在本机读到了正文，"
        f"{unavailable} 个读不到正文（正文可能在云端），"
        "后者不代表没有密钥。所有命中均已打码，本页只做检查，不会修改或删除任何数据。"
    )
    return {
        "results": results,
        "scanned": scanned,
        "unavailable": unavailable,
        "total_hits": total_hits,
        "by_severity": by_severity,
        "note": note,
    }
