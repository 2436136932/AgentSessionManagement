"""Export a session to a portable file before deleting it.

The point is confidence: a person should be able to keep a readable copy of a
conversation they are about to remove, without depending on the agent's own
cloud or on this tool.

Three formats, all built from the same read-only preview data:

  * markdown -- the default; a human-readable transcript with roles, kinds and
    timestamps, suitable for archiving or pasting elsewhere
  * json     -- the full structured preview payload, for re-processing
  * text     -- plain transcript with minimal decoration

Exports are written under `_data/exports/<agent>/<safe-sid>.<ext>` with the
timestamp in the filename, so repeated exports never overwrite each other.
This module performs no writes to any agent store.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from adapters.registry import get_adapter
from core.util import data_root, now_iso, stamp

FORMATS = ("markdown", "json", "text")

_ROLE_LABEL = {
    "user": "用户",
    "assistant": "助手",
    "tool": "工具",
    "system": "系统",
}
_KIND_LABEL = {
    "text": "",
    "reasoning": "思考",
    "tool-call": "工具调用",
    "tool-result": "工具结果",
    "image": "图片",
    "note": "备注",
}


def exports_root() -> Path:
    p = data_root() / "exports"
    p.mkdir(parents=True, exist_ok=True)
    return p


def safe_name(text: str, limit: int = 60) -> str:
    """A filename-safe version of an id or title."""
    s = re.sub(r"[^\w\u4e00-\u9fff.\-]+", "_", str(text or "")).strip("._")
    return (s[:limit] or "session")


def render_markdown(agent_label: str, sid: str, title: str, preview: dict,
                    session: dict | None = None) -> str:
    lines: list[str] = []
    lines.append(f"# {title or '(无标题)'}")
    lines.append("")
    lines.append(f"- Agent：{agent_label}")
    lines.append(f"- 会话 ID：`{sid}`")
    if session:
        for key, label in (
            ("cwd", "工作目录"),
            ("size_h", "占用空间"),
            ("created_iso", "创建时间"),
            ("updated_iso", "最后活动"),
        ):
            v = session.get(key)
            if v:
                lines.append(f"- {label}：{v}")
        flags = []
        if session.get("is_ghost"):
            flags.append("幽灵条目")
        if session.get("is_orphan"):
            flags.append("孤儿会话")
        if session.get("pinned"):
            flags.append("已标记保留")
        if flags:
            lines.append(f"- 标记：{'、'.join(flags)}")
    lines.append(f"- 导出时间：{now_iso()}")
    lines.append(f"- 消息条数：{preview.get('total_messages', 0)}")
    if preview.get("truncated"):
        lines.append("- 注意：导出时消息被截断（原会话更大）")
    if preview.get("reason"):
        lines.append("")
        lines.append(f"> {preview['reason']}")
    lines.append("")
    lines.append("---")
    lines.append("")

    for m in preview.get("messages") or []:
        role = _ROLE_LABEL.get(m.get("role"), m.get("role") or "")
        kind = _KIND_LABEL.get(m.get("kind"), m.get("kind") or "")
        head = f"## {role}"
        if kind:
            head += f" · {kind}"
        if m.get("tool"):
            head += f" · `{m['tool']}`"
        if m.get("is_error"):
            head += " · **出错**"
        lines.append(head)
        if m.get("time_iso"):
            lines.append(f"*{m['time_iso']}*")
        lines.append("")
        text = (m.get("text") or "").rstrip()
        if text:
            if m.get("kind") in ("tool-call", "tool-result"):
                lines.append("```")
                lines.append(text)
                lines.append("```")
            else:
                lines.append(text)
        else:
            lines.append("*(空)*")
        lines.append("")

    if not preview.get("messages"):
        lines.append("*没有可导出的消息内容。*")
        lines.append("")
    return "\n".join(lines)


def render_text(agent_label: str, sid: str, title: str, preview: dict) -> str:
    out: list[str] = [
        f"{title or '(无标题)'}",
        f"Agent: {agent_label}   会话 ID: {sid}",
        f"导出时间: {now_iso()}   消息: {preview.get('total_messages', 0)}",
        "=" * 72,
        "",
    ]
    if preview.get("reason"):
        out.extend([f"! {preview['reason']}", ""])
    for m in preview.get("messages") or []:
        who = _ROLE_LABEL.get(m.get("role"), m.get("role") or "")
        kind = _KIND_LABEL.get(m.get("kind"), "")
        tail = f" ({kind})" if kind else ""
        ts = m.get("time_iso") or ""
        out.append(f"[{who}{tail}] {ts}".rstrip())
        out.append(m.get("text") or "(空)")
        out.append("")
    if not preview.get("messages"):
        out.append("(没有可导出的消息内容)")
    return "\n".join(out)


def export(agent_id: str, sid: str, fmt: str = "markdown",
           session: dict | None = None) -> dict:
    """Write one session to disk. Returns a receipt."""
    if fmt not in FORMATS:
        raise ValueError(f"不支持的导出格式：{fmt}（可选：{', '.join(FORMATS)}）")

    adapter = get_adapter(agent_id)
    if adapter is None:
        raise ValueError(f"未知的 Agent：{agent_id}")

    preview = adapter.preview(sid)
    title = preview.get("title") or (session or {}).get("title") or ""

    outdir = exports_root() / safe_name(agent_id, 30)
    outdir.mkdir(parents=True, exist_ok=True)
    ext = {"markdown": "md", "json": "json", "text": "txt"}[fmt]
    name = f"{stamp()}-{safe_name(sid, 60)}.{ext}"
    path = outdir / name

    if fmt == "markdown":
        body = render_markdown(adapter.label, sid, title, preview, session)
    elif fmt == "text":
        body = render_text(adapter.label, sid, title, preview)
    else:
        body = json.dumps(
            {
                "exported_at": now_iso(),
                "agent": agent_id,
                "agent_label": adapter.label,
                "sid": sid,
                "session": session or {},
                "preview": preview,
            },
            ensure_ascii=False,
            indent=2,
        )

    path.write_text(body, encoding="utf-8")
    return {
        "ok": True,
        "path": str(path),
        "bytes": len(body.encode("utf-8")),
        "format": fmt,
        "title": title,
        "message_count": preview.get("total_messages", 0),
        "available": preview.get("available", False),
        "reason": preview.get("reason", ""),
    }


def list_exports(limit: int = 200) -> list[dict]:
    root = exports_root()
    out: list[dict] = []
    for p in sorted(root.rglob("*"), key=lambda x: x.stat().st_mtime if x.exists() else 0,
                    reverse=True):
        if not p.is_file():
            continue
        try:
            st = p.stat()
        except OSError:
            continue
        out.append(
            {
                "path": str(p),
                "name": p.name,
                "agent": p.parent.name,
                "bytes": st.st_size,
                "mtime": int(st.st_mtime * 1000),
                "mtime_iso": __import__("datetime").datetime.fromtimestamp(
                    st.st_mtime
                ).strftime("%Y-%m-%d %H:%M:%S"),
            }
        )
        if len(out) >= limit:
            break
    return out
