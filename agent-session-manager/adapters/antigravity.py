"""Antigravity Tools adapter.

Antigravity Tools is a local proxy/CLI wrapper. Its state lives in
~/.antigravity_tools as several small SQLite databases:

  thinking_store.db  thinking_sessions / thinking_records  <- session-ish
  token_stats.db     token_usage / token_stats_hourly      <- usage only
  user_tokens.db     user_tokens / token_ip_bindings ...
  proxy_logs.db      request_logs / tool_signatures
  security.db        ip_access_logs / ip_blacklist / ip_whitelist

Only `thinking_sessions` / `thinking_records` describe conversations; the rest
is accounting and must not be touched. On this machine all of these tables are
empty, so the adapter is mostly a detector -- but it is written to work when
they are populated.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from adapters.base import Adapter
from core.model import (
    KIND_SQLITE,
    DeleteAction,
    DeletePlan,
    Session,
)
from core.util import home, is_safe_session_id, safe_size


class AntigravityAdapter(Adapter):
    id = "antigravity"
    label = "Antigravity Tools"
    processes = ("antigravity tools.exe", "antigravity.exe")
    can_delete = True
    storage_hint = "~/.antigravity_tools"

    def base(self) -> Path:
        return home() / ".antigravity_tools"

    def db(self, name: str) -> Path:
        return self.base() / name

    def roots(self) -> list[Path]:
        return [self.base()]

    def detect(self) -> bool:
        return self.base().exists()

    # ------------------------------------------------------------------ sqlite

    def _connect(self, name: str) -> sqlite3.Connection | None:
        p = self.db(name)
        if not p.exists():
            return None
        try:
            con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
            con.row_factory = sqlite3.Row
            return con
        except sqlite3.Error:
            return None

    def _thinking_cols(self) -> list[str]:
        con = self._connect("thinking_store.db")
        if con is None:
            return []
        try:
            return [d[1] for d in con.execute('PRAGMA table_info("thinking_sessions")')]
        except sqlite3.Error:
            return []
        finally:
            con.close()

    # ------------------------------------------------------------------- scan

    def list_sessions(self) -> list[Session]:
        out: list[Session] = []
        con = self._connect("thinking_store.db")
        if con is None:
            return out
        try:
            cols = {d[1] for d in con.execute('PRAGMA table_info("thinking_sessions")')}
            if not cols:
                return out
            key = "id" if "id" in cols else next(iter(cols))
            sel = [c for c in ("id", "title", "name", "cwd", "created_at", "updated_at") if c in cols]
            if key not in sel:
                sel.insert(0, key)
            for r in con.execute(f'select {", ".join(sel)} from thinking_sessions'):
                d = dict(r)
                sid = str(d.get(key))
                out.append(
                    Session(
                        agent=self.id,
                        agent_label=self.label,
                        sid=sid,
                        title=str(d.get("title") or d.get("name") or "(无标题)"),
                        cwd=str(d.get("cwd") or ""),
                        created_at=_as_ms(d.get("created_at")),
                        updated_at=_as_ms(d.get("updated_at")),
                        size=safe_size(self.db("thinking_store.db")),
                        file_count=1,
                        paths=[str(self.db("thinking_store.db"))],
                    )
                )
        except sqlite3.Error:
            pass
        finally:
            con.close()
        return out

    # --------------------------------------------------------------- deletion

    def plan_delete(self, sid: str) -> DeletePlan:
        plan = self._plan(sid)
        if not is_safe_session_id(sid):
            plan.blocked = True
            plan.block_reason = f"非法会话 ID：{sid!r}"
            return plan

        con = self._connect("thinking_store.db")
        if con is None:
            plan.blocked = True
            plan.block_reason = "无法读取 thinking_store.db。"
            return plan
        try:
            cols = {d[1] for d in con.execute('PRAGMA table_info("thinking_sessions")')}
            if not cols:
                plan.blocked = True
                plan.block_reason = "thinking_sessions 表不存在。"
                return plan
            key = "id" if "id" in cols else next(iter(cols))
            row = con.execute(
                f'select "{key}" from thinking_sessions where "{key}" = ?', (sid,)
            ).fetchone()
            if row is None:
                plan.blocked = True
                plan.block_reason = "找不到该会话。"
                return plan

            db = self.db("thinking_store.db")
            plan.actions.append(
                DeleteAction(
                    kind=KIND_SQLITE,
                    path=f"{db} → thinking_sessions",
                    detail="删除会话行",
                    reversible=True,
                    db_path=str(db),
                    table="thinking_sessions",
                    key_col=key,
                    key_val=sid,
                )
            )
            rcols = {
                d[1]
                for d in con.execute('PRAGMA table_info("thinking_records")')
            }
            if "session_id" in rcols:
                n = con.execute(
                    "select count(*) from thinking_records where session_id = ?", (sid,)
                ).fetchone()[0]
                if n:
                    plan.actions.append(
                        DeleteAction(
                            kind=KIND_SQLITE,
                            path=f"{db} → thinking_records",
                            detail=f"删除该会话的 {n} 条思考记录",
                            reversible=True,
                            db_path=str(db),
                            table="thinking_records",
                            key_col="session_id",
                            key_val=sid,
                        )
                    )
            plan.warnings.append("仅清理会话数据，token 统计与安全日志不会被改动。")
        except sqlite3.Error as e:
            plan.blocked = True
            plan.block_reason = f"读取数据库失败：{e}"
        finally:
            con.close()

        if self.is_running():
            plan.blocked = True
            plan.block_reason = "Antigravity Tools 正在运行，请先退出后再删除。"
        return plan

    def iter_text(self, sid: str):
        """Unclipped searchable text from Antigravity thinking records."""
        con = self._connect("thinking_store.db")
        if con is None:
            return
        try:
            cols = {d[1] for d in con.execute('PRAGMA table_info("thinking_sessions")')}
            if not cols:
                return
            key = "id" if "id" in cols else next(iter(cols))
            row = con.execute(
                f'select * from thinking_sessions where "{key}" = ?', (sid,)
            ).fetchone()
            if row is not None:
                d = dict(row)
                t = d.get("title") or d.get("name")
                if t:
                    yield ("system", "title", str(t))

            rcols = {x[1] for x in con.execute('PRAGMA table_info("thinking_records")')}
            if "session_id" in rcols:
                for r in con.execute(
                    "select * from thinking_records where session_id = ?", (sid,)
                ):
                    rr = dict(r)
                    for cand in ("content", "text", "thinking", "body", "message"):
                        if rr.get(cand):
                            yield ("assistant", "reasoning", str(rr[cand]))
                            break
        except sqlite3.Error:
            pass
        finally:
            con.close()

    # --------------------------------------------------------------- preview

    def preview(self, sid: str) -> dict:
        """Render an Antigravity thinking session read-only.

        thinking_records carries the per-session reasoning entries; when a
        session has none, the session row itself is shown so the preview still
        explains what exists.
        """
        from core.model import PREVIEW_MESSAGE_LIMIT, Message, clip

        out: dict = {
            "agent": self.id,
            "sid": sid,
            "title": "",
            "available": False,
            "reason": "",
            "messages": [],
            "truncated": False,
            "total_messages": 0,
            "extra": {},
        }

        con = self._connect("thinking_store.db")
        if con is None:
            out["reason"] = "无法读取 thinking_store.db。"
            return out
        try:
            cols = {d[1] for d in con.execute('PRAGMA table_info("thinking_sessions")')}
            if not cols:
                out["reason"] = "thinking_sessions 表不存在。"
                return out
            key = "id" if "id" in cols else next(iter(cols))
            row = con.execute(
                f'select * from thinking_sessions where "{key}" = ?', (sid,)
            ).fetchone()
            if row is None:
                out["reason"] = "找不到该会话。"
                return out
            d = dict(row)
            out["title"] = str(d.get("title") or d.get("name") or "").strip() or "(无标题)"

            msgs: list[Message] = []
            rcols = {x[1] for x in con.execute('PRAGMA table_info("thinking_records")')}
            if "session_id" in rcols:
                order = "rowid"
                try:
                    recs = list(
                        con.execute(
                            f'select * from thinking_records where session_id = ? order by {order}',
                            (sid,),
                        )
                    )
                except sqlite3.Error:
                    recs = []
                for r in recs:
                    rr = dict(r)
                    text = ""
                    for cand in ("content", "text", "thinking", "body", "message"):
                        if rr.get(cand):
                            text = str(rr[cand])
                            break
                    if not text:
                        text = json.dumps(rr, ensure_ascii=False, default=str)
                    t, c = clip(text)
                    msgs.append(
                        Message(
                            "assistant",
                            t,
                            _as_ms(rr.get("created_at") or rr.get("timestamp")),
                            "reasoning",
                            truncated=c,
                        )
                    )

            if not msgs:
                shown = [
                    f"{k}：{v}" for k, v in d.items() if v not in (None, "", 0)
                ]
                msgs.append(
                    Message(
                        "system",
                        "\n".join(shown) or "（该行没有除 id 之外的可读字段）",
                        _as_ms(d.get("updated_at") or d.get("created_at")),
                        "note",
                    )
                )

            out["total_messages"] = len(msgs)
            if len(msgs) > PREVIEW_MESSAGE_LIMIT:
                out["messages"] = [m.to_dict() for m in msgs[:PREVIEW_MESSAGE_LIMIT]]
                out["truncated"] = True
            else:
                out["messages"] = [m.to_dict() for m in msgs]
            out["available"] = True
            out["extra"] = {
                "db_path": str(self.db("thinking_store.db")),
                "record_count": max(0, len(msgs) - 1),
                "note": "仅显示 thinking_sessions / thinking_records；token 统计与安全日志不在此范围。",
            }
            if not any(m.kind == "reasoning" for m in msgs):
                out["reason"] = "该会话没有思考记录，下面是它的元数据。"
        except sqlite3.Error as e:
            out["reason"] = f"读取数据库失败：{e}"
        finally:
            con.close()
        return out

    # --------------------------------------------------------------- verify

    def verify_absent(self, sid: str) -> tuple[bool, str]:
        con = self._connect("thinking_store.db")
        if con is None:
            return True, "数据库不存在，视为已删除。"
        try:
            cols = {d[1] for d in con.execute('PRAGMA table_info("thinking_sessions")')}
            if not cols:
                return True, "thinking_sessions 表不存在。"
            key = "id" if "id" in cols else next(iter(cols))
            n = con.execute(
                f'select count(*) from thinking_sessions where "{key}" = ?', (sid,)
            ).fetchone()[0]
            if n:
                return False, "thinking_sessions 中仍存在该会话。"
            rcols = {d[1] for d in con.execute('PRAGMA table_info("thinking_records")')}
            if "session_id" in rcols:
                m = con.execute(
                    "select count(*) from thinking_records where session_id = ?", (sid,)
                ).fetchone()[0]
                if m:
                    return False, f"thinking_records 中仍残留 {m} 条记录。"
            return True, "会话与其思考记录均已删除。"
        except sqlite3.Error as e:
            return False, f"校验失败：{e}"
        finally:
            con.close()

    # --------------------------------------------------------------- health

    def health(self) -> list[dict]:
        findings: list[dict] = []
        # Fully empty databases still occupy a file each.
        for name in (
            "thinking_store.db",
            "token_stats.db",
            "user_tokens.db",
            "proxy_logs.db",
            "security.db",
        ):
            p = self.db(name)
            if not p.exists():
                continue
            con = self._connect(name)
            if con is None:
                continue
            try:
                names = [
                    r[0]
                    for r in con.execute(
                        "select name from sqlite_master where type='table' "
                        "and name not like 'sqlite_%'"
                    )
                ]
                total = 0
                for t in names:
                    try:
                        total += con.execute(f'select count(*) from "{t}"').fetchone()[0]
                    except sqlite3.Error:
                        pass
                if total == 0 and names:
                    findings.append(
                        {
                            "agent": self.id,
                            "level": "info",
                            "kind": "empty_db",
                            "title": f"{name} 为空数据库",
                            "detail": "所有表都没有数据，但文件仍占用空间。",
                            "items": [str(p)],
                            "size": safe_size(p),
                            "action": "",
                        }
                    )
            except sqlite3.Error:
                pass
            finally:
                con.close()
        return findings


def _as_ms(v) -> int | None:
    if v is None:
        return None
    if isinstance(v, (int, float)):
        iv = int(v)
        if iv <= 0:
            return None
        # Seconds vs milliseconds heuristic.
        return iv if iv > 10_000_000_000 else iv * 1000
    return None
