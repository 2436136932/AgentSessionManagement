"""GitHub Copilot Chat / VS Code chat adapter.

VS Code keeps chat sessions in three places, and all three matter:

  * %APPDATA%/Code/User/globalStorage/github.copilot-chat/session-store.db
    A SQLite database with sessions / turns / checkpoints / session_files /
    session_refs and an FTS5 virtual table `search_index`.

  * %APPDATA%/Code/User/globalStorage/emptyWindowChatSessions/*.jsonl
    One append-only JSONL file per chat session (also used by other chat
    participants). The first line (kind 0) carries sessionId and creationDate.

  * %APPDATA%/Code/User/globalStorage/state.vscdb
    VS Code's own global state store. The key `chat.ChatSessionStore.index`
    holds {"version":1,"entries":{"<sessionId>":{...}}} and it is what the
    chat list is rendered from.

Two invisible residues live here, and both are reproducible on this machine:

  1. The FTS table: deleting only the `sessions` row leaves the transcript text
     findable in VS Code's chat search.
  2. The state.vscdb index: deleting only the .jsonl file leaves an entry in
     `chat.ChatSessionStore.index`, so the chat still appears in the list and
     fails to open. Observed live: an "agent-host-copilotcli:/untitled-..."
     entry with no file on disk at all.

So a plan removes the DB rows, the FTS rows, the chat file, AND the matching
index entry -- and a restore puts all of them back.

Deletion is guarded: VS Code must not be running, because it holds both
databases open and rewrites them on exit.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path

from adapters.base import Adapter
from core.model import (
    KIND_FILE,
    KIND_SQLITE,
    DeleteAction,
    DeletePlan,
    Session,
)
from core.util import (
    is_safe_session_id,
    list_files,
    read_json,
    roaming_appdata,
    safe_size,
)

#: Tables that reference a session by column `session_id`.
_SESSION_CHILD_TABLES = ("turns", "checkpoints", "session_files", "session_refs")

#: Key in state.vscdb holding the chat list index.
CHAT_INDEX_KEY = "chat.ChatSessionStore.index"


class CopilotChatAdapter(Adapter):
    id = "copilot-chat"
    label = "GitHub Copilot Chat (VS Code)"
    processes = ("code.exe", "code - insiders.exe")
    can_delete = True
    storage_hint = "%APPDATA%/Code/User/globalStorage"

    def global_storage(self) -> Path:
        return roaming_appdata() / "Code" / "User" / "globalStorage"

    def db_path(self) -> Path:
        return self.global_storage() / "github.copilot-chat" / "session-store.db"

    def jsonl_dir(self) -> Path:
        return self.global_storage() / "emptyWindowChatSessions"

    def transcript_dir(self) -> Path:
        # Newer VS Code builds keep per-session transcript folders here.
        return self.global_storage() / "github.copilot-chat" / "transcripts"

    def state_db(self) -> Path:
        """VS Code's global state store (holds the chat list index)."""
        return roaming_appdata() / "Code" / "User" / "globalStorage" / "state.vscdb"

    # ------------------------------------------------------- state.vscdb index

    def _read_chat_index(self) -> dict[str, dict]:
        """Return {sessionId: entry} from state.vscdb, or {} when unreadable."""
        p = self.state_db()
        if not p.exists():
            return {}
        try:
            con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        except sqlite3.Error:
            return {}
        try:
            row = con.execute(
                "select value from ItemTable where key = ?", (CHAT_INDEX_KEY,)
            ).fetchone()
        except sqlite3.Error:
            return {}
        finally:
            con.close()
        if not row or row[0] is None:
            return {}
        raw = row[0]
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", "replace")
        try:
            obj = json.loads(raw)
        except (ValueError, TypeError):
            return {}
        entries = obj.get("entries") if isinstance(obj, dict) else None
        if not isinstance(entries, dict):
            return {}
        return {k: v for k, v in entries.items() if isinstance(v, dict)}

    def _index_ids(self) -> set[str]:
        return set(self._read_chat_index().keys())

    def roots(self) -> list[Path]:
        return [self.global_storage(), roaming_appdata() / "Code" / "User" / "workspaceStorage"]

    def detect(self) -> bool:
        return self.db_path().exists() or self.jsonl_dir().exists() or self.transcript_dir().exists()

    # ------------------------------------------------------------------ sqlite

    def _connect(self) -> sqlite3.Connection | None:
        p = self.db_path()
        if not p.exists():
            return None
        try:
            con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
            con.row_factory = sqlite3.Row
            return con
        except sqlite3.Error:
            return None

    @staticmethod
    def _tables(con: sqlite3.Connection) -> set[str]:
        try:
            return {
                r[0]
                for r in con.execute("select name from sqlite_master where type in ('table','view')")
            }
        except sqlite3.Error:
            return set()

    # ------------------------------------------------------------------- scan

    def list_sessions(self) -> list[Session]:
        out: list[Session] = []
        seen: set[str] = set()

        con = self._connect()
        if con is not None:
            try:
                tabs = self._tables(con)
                if "sessions" in tabs:
                    cols = {d[1] for d in con.execute('PRAGMA table_info("sessions")')}
                    sel = [
                        c
                        for c in (
                            "id", "cwd", "repository", "branch", "summary",
                            "agent_name", "created_at", "updated_at",
                        )
                        if c in cols
                    ]
                    counts: dict[str, int] = {}
                    if "turns" in tabs:
                        try:
                            for r in con.execute(
                                "select session_id, count(*) from turns group by session_id"
                            ):
                                counts[str(r[0])] = int(r[1] or 0)
                        except sqlite3.Error:
                            pass
                    for r in con.execute(f'select {", ".join(sel)} from sessions'):
                        d = dict(r)
                        sid = str(d.get("id"))
                        seen.add(sid)
                        out.append(
                            Session(
                                agent=self.id,
                                agent_label=self.label,
                                sid=sid,
                                title=(d.get("summary") or d.get("agent_name") or "").strip()
                                or "(无标题)",
                                cwd=str(d.get("cwd") or ""),
                                created_at=_as_ms(d.get("created_at")),
                                updated_at=_as_ms(d.get("updated_at")),
                                size=safe_size(self.db_path()),
                                file_count=1,
                                paths=[str(self.db_path())],
                                extra={
                                    "turns": counts.get(sid, 0),
                                    "repository": d.get("repository"),
                                    "branch": d.get("branch"),
                                },
                            )
                        )
            except sqlite3.Error:
                pass
            finally:
                con.close()

        # JSONL chat sessions (emptyWindowChatSessions).
        for f in list_files(self.jsonl_dir(), ".jsonl"):
            sid, created, reqs = self._read_jsonl_meta(f)
            if not sid:
                sid = f.stem
            if sid in seen:
                continue
            seen.add(sid)
            out.append(
                Session(
                    agent=self.id,
                    agent_label=self.label,
                    sid=sid,
                    title=f"VS Code 聊天会话（{reqs} 条提问）" if reqs else "VS Code 聊天会话",
                    created_at=created,
                    updated_at=int(f.stat().st_mtime * 1000),
                    size=safe_size(f),
                    file_count=1,
                    paths=[str(f)],
                    note="",
                    extra={"source": "emptyWindowChatSessions", "file": str(f)},
                )
            )

        # Entries in VS Code's own chat index that have no file on disk.
        # These show up in the chat list but cannot be opened -- the same class
        # of residue as a DSH ghost, just in a different store.
        for sid, entry in self._read_chat_index().items():
            if sid in seen:
                continue
            seen.add(sid)
            out.append(
                Session(
                    agent=self.id,
                    agent_label=self.label,
                    sid=sid,
                    title=str(entry.get("title") or "").strip() or "(VS Code 聊天索引残留)",
                    created_at=entry.get("lastMessageDate") or (
                        (entry.get("timing") or {}).get("created")
                        if isinstance(entry.get("timing"), dict)
                        else None
                    ),
                    updated_at=entry.get("lastMessageDate"),
                    size=0,
                    file_count=0,
                    paths=[str(self.state_db())],
                    is_ghost=True,
                    note="VS Code 聊天列表索引中有记录，但磁盘上已无对应文件。",
                    extra={"source": "state.vscdb", "key": CHAT_INDEX_KEY, "entry": entry},
                )
            )

        out.sort(key=lambda s: -(s.updated_at or 0))
        return out

    def _read_jsonl_meta(self, f: Path) -> tuple[str, int | None, int]:
        """First line of a VS Code chat jsonl carries the session header."""
        sid = ""
        created: int | None = None
        reqs = 0
        try:
            with open(f, "r", encoding="utf-8", errors="replace") as fh:
                first = fh.readline().strip()
                if first:
                    try:
                        o = __import__("json").loads(first)
                        v = o.get("v") or {}
                        sid = str(v.get("sessionId") or "")
                        created = v.get("creationDate")
                        reqs = len(v.get("requests") or [])
                    except ValueError:
                        pass
        except OSError:
            pass
        return sid, created, reqs

    # --------------------------------------------------------------- deletion

    def plan_delete(self, sid: str) -> DeletePlan:
        plan = self._plan(sid)
        db = self.db_path()
        found = False
        # A VS Code chat id may contain ":" or "/" (e.g.
        # "agent-host-copilotcli:/untitled-..."). Those are fine as index keys
        # but must never be turned into a filename.
        path_safe = is_safe_session_id(sid)

        # Part 1: SQLite rows (sessions, children, FTS).
        con = self._connect()
        if con is not None:
            try:
                tabs = self._tables(con)
                if "sessions" in tabs:
                    row = con.execute(
                        "select id, summary, agent_name from sessions where id = ?", (sid,)
                    ).fetchone()
                    if row is not None:
                        found = True
                        plan.title = (row["summary"] or row["agent_name"] or "").strip()
                        plan.actions.append(
                            DeleteAction(
                                kind=KIND_SQLITE,
                                path=f"{db} → sessions",
                                detail="删除 sessions 表中的会话行",
                                reversible=True,
                                db_path=str(db),
                                table="sessions",
                                key_col="id",
                                key_val=sid,
                            )
                        )
                        for t in _SESSION_CHILD_TABLES:
                            if t not in tabs:
                                continue
                            try:
                                n = con.execute(
                                    f'select count(*) from "{t}" where session_id = ?', (sid,)
                                ).fetchone()[0]
                            except sqlite3.Error:
                                continue
                            if n:
                                plan.actions.append(
                                    DeleteAction(
                                        kind=KIND_SQLITE,
                                        path=f"{db} → {t}",
                                        detail=f"删除该会话的 {n} 条关联记录",
                                        reversible=True,
                                        db_path=str(db),
                                        table=t,
                                        key_col="session_id",
                                        key_val=sid,
                                    )
                                )
                        # FTS full-text index -- the invisible residue.
                        if "search_index" in tabs:
                            try:
                                n = con.execute(
                                    "select count(*) from search_index where session_id = ?", (sid,)
                                ).fetchone()[0]
                            except sqlite3.Error:
                                n = 0
                            if n:
                                plan.actions.append(
                                    DeleteAction(
                                        kind=KIND_SQLITE,
                                        path=f"{db} → search_index (FTS5)",
                                        detail=f"删除全文搜索索引中的 {n} 条记录（否则仍能搜到已删内容）",
                                        reversible=True,
                                        db_path=str(db),
                                        table="search_index",
                                        key_col="session_id",
                                        key_val=sid,
                                    )
                                )
            except sqlite3.Error:
                pass
            finally:
                con.close()

        # Part 2: JSONL chat session files.
        if path_safe:
            for f in list_files(self.jsonl_dir(), ".jsonl"):
                fsid, _c, _r = self._read_jsonl_meta(f)
                if fsid == sid or f.stem == sid:
                    found = True
                    plan.actions.append(
                        DeleteAction(
                            kind=KIND_FILE,
                            path=str(f),
                            detail="VS Code 聊天会话文件",
                            size=safe_size(f),
                            reversible=True,
                        )
                    )

        # Part 3: transcript folders, if this VS Code build creates them.
        tdir = self.transcript_dir()
        if path_safe and tdir.exists():
            for d in tdir.iterdir():
                if d.is_dir() and d.name == sid:
                    found = True
                    plan.actions.append(
                        DeleteAction(
                            kind=KIND_FILE if d.is_file() else "remove_dir",
                            path=str(d),
                            detail="会话文本记录目录",
                            size=safe_size(d),
                            reversible=True,
                        )
                    )

        # Part 4: the entry in VS Code's own chat list index. Without this the
        # chat keeps appearing in the list and cannot be opened.
        index_entry = self._read_chat_index().get(sid)
        if index_entry is not None:
            found = True
            if not plan.title:
                plan.title = str(index_entry.get("title") or "").strip()
            plan.actions.append(
                DeleteAction(
                    kind=KIND_SQLITE,
                    path=f"{self.state_db()} → {CHAT_INDEX_KEY}",
                    detail="从 VS Code 聊天列表索引中移除该会话（否则列表里残留点不开的条目）",
                    reversible=True,
                    db_path=str(self.state_db()),
                    table="__vscode_chat_index__",
                    key_col=CHAT_INDEX_KEY,
                    key_val=sid,
                )
            )

        if not found:
            plan.blocked = True
            plan.block_reason = "在 Copilot 数据库、聊天文件与 VS Code 聊天索引中都找不到该会话。"
            return plan

        live = self.is_running()
        if live:
            plan.blocked = True
            plan.block_reason = (
                "VS Code 正在运行。它持有 session-store.db 与 state.vscdb 并在退出时重写，"
                "请先完全关闭 VS Code 再删除。"
            )
        else:
            plan.warnings.append(
                "删除后 VS Code 的聊天搜索索引与聊天列表索引会同步更新；如未生效可重启 VS Code。"
            )
        return plan

    def iter_text(self, sid: str):
        """Unclipped searchable text from Copilot / VS Code chat stores."""
        entry = self._read_chat_index().get(sid)
        if isinstance(entry, dict) and entry.get("title"):
            yield ("system", "title", str(entry["title"]))

        # Database turns.
        con = self._connect()
        if con is not None:
            try:
                tabs = self._tables(con)
                if "sessions" in tabs:
                    row = con.execute(
                        "select summary, cwd from sessions where id = ?", (sid,)
                    ).fetchone()
                    if row is not None:
                        if row["summary"]:
                            yield ("system", "title", str(row["summary"]))
                        if row["cwd"]:
                            yield ("system", "cwd", str(row["cwd"]))
                if "turns" in tabs:
                    for r in con.execute(
                        "select user_message, assistant_response from turns "
                        "where session_id = ? order by turn_index",
                        (sid,),
                    ):
                        if r["user_message"]:
                            yield ("user", "text", str(r["user_message"]))
                        if r["assistant_response"]:
                            yield ("assistant", "text", str(r["assistant_response"]))
                if "checkpoints" in tabs:
                    try:
                        for c in con.execute(
                            "select title, overview, work_done, technical_details, "
                            "next_steps, important_files from checkpoints "
                            "where session_id = ?",
                            (sid,),
                        ):
                            for key in (
                                "title", "overview", "work_done",
                                "technical_details", "next_steps", "important_files",
                            ):
                                v = c[key]
                                if v:
                                    yield ("assistant", f"checkpoint-{key}", str(v))
                    except sqlite3.Error:
                        pass
                if "session_files" in tabs:
                    try:
                        paths = [
                            str(r[0])
                            for r in con.execute(
                                "select distinct file_path from session_files "
                                "where session_id = ?",
                                (sid,),
                            )
                        ]
                        if paths:
                            yield ("tool", "files", "\n".join(paths))
                    except sqlite3.Error:
                        pass
            except sqlite3.Error:
                pass
            finally:
                con.close()

        # JSONL chat file: the header's `requests` array holds the transcript.
        if is_safe_session_id(sid):
            for f in list_files(self.jsonl_dir(), ".jsonl"):
                fsid, _c, reqs = self._read_jsonl_meta(f)
                if not (fsid == sid or f.stem == sid):
                    continue
                if isinstance(reqs, list):
                    for req in reqs:
                        if not isinstance(req, dict):
                            continue
                        msg = req.get("message")
                        if isinstance(msg, dict) and msg.get("text"):
                            yield ("user", "text", str(msg["text"]))
                        resp = req.get("response")
                        if isinstance(resp, list):
                            for r in resp:
                                if not isinstance(r, dict):
                                    continue
                                v = r.get("value")
                                if isinstance(v, dict) and isinstance(v.get("value"), str):
                                    yield ("assistant", "text", v["value"])
                                elif isinstance(v, str):
                                    yield ("assistant", "text", v)

    # --------------------------------------------------------------- preview

    def preview(self, sid: str) -> dict:
        """Render a VS Code chat read-only.

        Three sources, in order of usefulness:
          1. session-store.db turns (user_message / assistant_response rows)
          2. the emptyWindowChatSessions jsonl, whose header carries the
             `requests` array when the chat has content
          3. state.vscdb, which for an index-only ghost has nothing but the
             title and timestamps
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

        msgs: list[Message] = []
        sources: list[str] = []
        index_entry = self._read_chat_index().get(sid)

        # --- 1. database turns ------------------------------------------------
        con = self._connect()
        if con is not None:
            try:
                tabs = self._tables(con)
                if "sessions" in tabs:
                    row = con.execute(
                        "select summary, agent_name, cwd, created_at, updated_at "
                        "from sessions where id = ?",
                        (sid,),
                    ).fetchone()
                    if row is not None:
                        out["title"] = (row["summary"] or row["agent_name"] or "").strip()
                if "turns" in tabs:
                    rows = list(
                        con.execute(
                            "select turn_index, user_message, assistant_response, timestamp "
                            "from turns where session_id = ? order by turn_index",
                            (sid,),
                        )
                    )
                    if rows:
                        sources.append("session-store.db turns")
                    for r in rows:
                        if r["user_message"]:
                            t, c = clip(str(r["user_message"]))
                            msgs.append(Message("user", t, r["timestamp"], "text", truncated=c))
                        if r["assistant_response"]:
                            t, c = clip(str(r["assistant_response"]))
                            msgs.append(
                                Message("assistant", t, r["timestamp"], "text", truncated=c)
                            )
                if "checkpoints" in tabs:
                    try:
                        cps = list(
                            con.execute(
                                "select checkpoint_number, title, overview "
                                "from checkpoints where session_id = ? "
                                "order by checkpoint_number",
                                (sid,),
                            )
                        )
                    except sqlite3.Error:
                        cps = []
                    if cps:
                        sources.append("checkpoints")
                        for c in cps:
                            body = f"{c['title'] or ''}\n{c['overview'] or ''}".strip()
                            t, cl = clip(body, 1500)
                            msgs.append(
                                Message(
                                    "assistant",
                                    t,
                                    None,
                                    "note",
                                    tool=f"检查点 {c['checkpoint_number']}",
                                    truncated=cl,
                                )
                            )
            except sqlite3.Error:
                pass
            finally:
                con.close()

        # --- 2. jsonl chat file ----------------------------------------------
        if is_safe_session_id(sid):
            for f in list_files(self.jsonl_dir(), ".jsonl"):
                fsid, created, reqs = self._read_jsonl_meta(f)
                if not (fsid == sid or f.stem == sid):
                    continue
                if not msgs and reqs:
                    for i, req in enumerate(reqs):
                        if not isinstance(req, dict):
                            continue
                        msg = req.get("message") or {}
                        text = msg.get("text") if isinstance(msg, dict) else None
                        if text:
                            t, c = clip(str(text))
                            msgs.append(
                                Message("user", t, req.get("timestamp"), "text", truncated=c)
                            )
                        resp = req.get("response") or []
                        for r in resp if isinstance(resp, list) else []:
                            if not isinstance(r, dict):
                                continue
                            parts = r.get("value") if isinstance(r.get("value"), dict) else {}
                            for k in ("value", "text"):
                                v = parts.get(k) if isinstance(parts, dict) else None
                                if isinstance(v, str) and v.strip():
                                    t, c = clip(v)
                                    msgs.append(
                                        Message(
                                            "assistant",
                                            t,
                                            req.get("timestamp"),
                                            "text",
                                            truncated=c,
                                        )
                                    )
                                    break
                sources.append(f"emptyWindowChatSessions/{f.name}")

        # --- 3. state.vscdb index entry --------------------------------------
        if index_entry is not None:
            if not out["title"]:
                out["title"] = str(index_entry.get("title") or "").strip()
            sources.append(f"state.vscdb:{CHAT_INDEX_KEY}")

        out["title"] = out["title"] or "(无标题)"
        out["extra"] = {
            "sources": sources,
            "index_entry": index_entry or {},
            "requests_in_file": len(
                (index_entry or {}).get("requests") or []
            ),
            "db_path": str(self.db_path()),
            "state_db": str(self.state_db()),
            "jsonl_dir": str(self.jsonl_dir()),
        }

        out["total_messages"] = len(msgs)
        if len(msgs) > PREVIEW_MESSAGE_LIMIT:
            out["messages"] = [m.to_dict() for m in msgs[:PREVIEW_MESSAGE_LIMIT]]
            out["truncated"] = True
        else:
            out["messages"] = [m.to_dict() for m in msgs]

        has_file = any(
            s.startswith("emptyWindowChatSessions/") for s in sources
        )
        if msgs:
            out["available"] = True
        elif index_entry is not None and not has_file:
            # Index-only: the chat is listed but has no backing data at all.
            out["available"] = True
            out["reason"] = (
                "这是 VS Code 聊天列表里的残留条目：索引中有记录，但磁盘上既没有会话文件、"
                "数据库里也没有消息内容，因此无内容可预览。"
            )
        elif has_file:
            # A real chat file that simply holds no messages yet.
            out["available"] = True
            out["reason"] = (
                "该会话文件存在，但其中没有任何消息（对话可能从未真正开始，或内容尚未写入）。"
            )
        else:
            out["reason"] = "在数据库与聊天文件中都没有找到该会话的消息内容。"
        return out

    # --------------------------------------------------------------- verify

    def verify_absent(self, sid: str) -> tuple[bool, str]:
        con = self._connect()
        if con is not None:
            try:
                tabs = self._tables(con)
                if "sessions" in tabs:
                    n = con.execute(
                        "select count(*) from sessions where id = ?", (sid,)
                    ).fetchone()[0]
                    if n:
                        return False, "sessions 表中仍存在该会话行。"
                if "search_index" in tabs:
                    try:
                        m = con.execute(
                            "select count(*) from search_index where session_id = ?", (sid,)
                        ).fetchone()[0]
                        if m:
                            return False, f"全文索引中仍残留 {m} 条记录。"
                    except sqlite3.Error:
                        pass
            except sqlite3.Error:
                pass
            finally:
                con.close()

        if is_safe_session_id(sid):
            for f in list_files(self.jsonl_dir(), ".jsonl"):
                fsid, _c, _r = self._read_jsonl_meta(f)
                if fsid == sid or f.stem == sid:
                    return False, "聊天会话文件仍然存在。"

        if sid in self._index_ids():
            return False, "VS Code 聊天列表索引中仍残留该会话条目。"
        return True, "数据库行、全文索引、聊天文件与 VS Code 聊天索引均已清除。"

    # --------------------------------------------------------------- health

    def health(self) -> list[dict]:
        findings: list[dict] = []
        con = self._connect()
        if con is None:
            return findings
        try:
            tabs = self._tables(con)
            if "search_index" in tabs and "sessions" in tabs:
                try:
                    n = con.execute(
                        "select count(*) from search_index where session_id not in "
                        "(select id from sessions)"
                    ).fetchone()[0]
                except sqlite3.Error:
                    n = 0
                if n:
                    findings.append(
                        {
                            "agent": self.id,
                            "level": "warn",
                            "kind": "fts_orphan",
                            "title": f"{n} 条孤立的全文索引记录",
                            "detail": "会话已不存在，但其内容仍能被聊天搜索搜到。",
                            "items": [],
                            "size": safe_size(self.db_path()),
                            "action": "",
                        }
                    )
            wal = Path(str(self.db_path()) + "-wal")
            if wal.exists() and safe_size(wal) > 16 * 1024 * 1024:
                findings.append(
                    {
                        "agent": self.id,
                        "level": "info",
                        "kind": "wal",
                        "title": f"数据库日志 {wal.name} 偏大",
                        "detail": "正常退出 VS Code 后通常会自动收缩。",
                        "items": [str(wal)],
                        "size": safe_size(wal),
                        "action": "",
                    }
                )
        except sqlite3.Error:
            pass
        finally:
            con.close()
        return findings

    def backup_db(self, dest_dir: Path) -> Path | None:
        """Consistent copy of the database.

        Connections are closed explicitly: `with sqlite3.connect(...)` commits
        but does not close, leaving the copy locked on Windows.
        """
        src = self.db_path()
        if not src.exists():
            return None
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / src.name
        s = d = None
        try:
            s = sqlite3.connect(str(src))
            d = sqlite3.connect(str(dest))
            s.backup(d)
            d.commit()
            return dest
        except sqlite3.Error:
            try:
                shutil.copy2(src, dest)
                return dest
            except OSError:
                return None
        finally:
            for con in (d, s):
                try:
                    if con is not None:
                        con.close()
                except sqlite3.Error:
                    pass


def _as_ms(v) -> int | None:
    """Timestamps appear as epoch-ms ints or ISO strings depending on build."""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        iv = int(v)
        return iv if iv > 0 else None
    if isinstance(v, str):
        s = v.strip().replace("Z", "+00:00")
        try:
            from datetime import datetime

            return int(datetime.fromisoformat(s).timestamp() * 1000)
        except ValueError:
            return None
    return None
