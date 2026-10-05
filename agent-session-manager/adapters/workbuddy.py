"""WorkBuddy (Tencent) adapter.

Storage: a SQLite database at ~/.workbuddy/workbuddy.db with a `sessions`
table (40 columns) plus `session_usage`.

Two things make this agent different from DSH:

  * The database carries a `deleted_at` column. Observed values are -1 for
    "live" rows, so this is a SOFT-DELETE column. Setting the flag alone does
    not reclaim space and does not remove the row, which is one of the ways
    "deleted" sessions keep accumulating.
  * Conversation bodies are not stored locally at all -- only titles,
    timestamps and per-session settings. So deleting a WorkBuddy session
    reclaims very little disk; the visible effect is a cleaner session list.

Because the payload is metadata, deletion here means: remove the row, remove
its usage row, and vacuum the database to actually release the pages. The
database is copied to quarantine first so the operation stays reversible.
"""

from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path

from adapters.base import Adapter
from core.model import (
    KIND_SQLITE,
    DeleteAction,
    DeletePlan,
    Session,
)
from core.util import home, is_safe_session_id, ms_to_iso, safe_size


def _ms(v) -> str:
    """Human-readable local time for an epoch-ms column, or ''."""
    return ms_to_iso(v) if isinstance(v, (int, float)) else ""


class WorkBuddyAdapter(Adapter):
    id = "workbuddy"
    label = "WorkBuddy"
    processes = ("workbuddy.exe",)
    can_delete = True
    storage_hint = "~/.workbuddy/workbuddy.db"

    def base(self) -> Path:
        return home() / ".workbuddy"

    def db_path(self) -> Path:
        return self.base() / "workbuddy.db"

    def roots(self) -> list[Path]:
        return [self.base()]

    def detect(self) -> bool:
        return self.db_path().exists()

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
    def _has_table(con: sqlite3.Connection, name: str) -> bool:
        try:
            row = con.execute(
                "select 1 from sqlite_master where type='table' and name=?", (name,)
            ).fetchone()
            return row is not None
        except sqlite3.Error:
            return False

    @staticmethod
    def _has_column(con: sqlite3.Connection, table: str, col: str) -> bool:
        try:
            return any(d[1] == col for d in con.execute(f'PRAGMA table_info("{table}")'))
        except sqlite3.Error:
            return False

    # ------------------------------------------------------------------- scan

    def list_sessions(self) -> list[Session]:
        out: list[Session] = []
        con = self._connect()
        if con is None:
            return out
        try:
            if not self._has_table(con, "sessions"):
                return out
            cols = {d[1] for d in con.execute('PRAGMA table_info("sessions")')}
            sel = [
                c
                for c in (
                    "id", "cwd", "title", "custom_title", "status",
                    "created_at", "updated_at", "last_activity_at",
                    "deleted_at", "is_playground", "mode", "model", "expert_id",
                )
                if c in cols
            ]
            rows = list(con.execute(f'select {", ".join(sel)} from sessions'))
            usage: dict[str, int] = {}
            if self._has_table(con, "session_usage"):
                try:
                    for r in con.execute("select session_id, size from session_usage"):
                        usage[str(r[0])] = int(r[1] or 0)
                except sqlite3.Error:
                    pass

            for r in rows:
                d = dict(r)
                sid = str(d.get("id"))
                deleted = d.get("deleted_at")
                # -1 / None / 0 observed to mean "not deleted".
                is_deleted = isinstance(deleted, int) and deleted > 0
                title = (d.get("custom_title") or d.get("title") or "").strip()
                out.append(
                    Session(
                        agent=self.id,
                        agent_label=self.label,
                        sid=sid,
                        title=title or "(无标题)",
                        cwd=str(d.get("cwd") or ""),
                        created_at=d.get("created_at"),
                        updated_at=d.get("updated_at") or d.get("last_activity_at"),
                        size=usage.get(sid, 0),
                        file_count=0,
                        paths=[str(self.db_path())],
                        is_ghost=is_deleted,
                        note="已在应用内标记删除（软删除），行仍占用数据库空间。"
                        if is_deleted
                        else "",
                        extra={
                            "status": d.get("status"),
                            "model": d.get("model"),
                            "mode": d.get("mode"),
                            "soft_deleted": is_deleted,
                        },
                    )
                )
        except sqlite3.Error:
            pass
        finally:
            con.close()
        out.sort(key=lambda s: -(s.updated_at or 0))
        return out

    # --------------------------------------------------------------- deletion

    def plan_delete(self, sid: str) -> DeletePlan:
        plan = self._plan(sid)
        if not is_safe_session_id(sid):
            plan.blocked = True
            plan.block_reason = f"非法会话 ID：{sid!r}"
            return plan

        con = self._connect()
        if con is None:
            plan.blocked = True
            plan.block_reason = "无法以只读方式打开 workbuddy.db。"
            return plan
        try:
            if not self._has_table(con, "sessions"):
                plan.blocked = True
                plan.block_reason = "workbuddy.db 中没有 sessions 表，格式与预期不符。"
                return plan
            row = con.execute(
                "select id, title, custom_title from sessions where id = ?", (sid,)
            ).fetchone()
            if row is None:
                plan.blocked = True
                plan.block_reason = "数据库中找不到该会话。"
                return plan
            plan.title = (row["custom_title"] or row["title"] or "").strip()

            db = self.db_path()
            plan.actions.append(
                DeleteAction(
                    kind=KIND_SQLITE,
                    path=f"{db} → sessions",
                    detail="删除 sessions 表中的该会话行",
                    size=0,
                    reversible=True,
                    db_path=str(db),
                    table="sessions",
                    key_col="id",
                    key_val=sid,
                )
            )

            if self._has_table(con, "session_usage"):
                try:
                    n = con.execute(
                        "select count(*) from session_usage where session_id = ?", (sid,)
                    ).fetchone()[0]
                    if n:
                        plan.actions.append(
                            DeleteAction(
                                kind=KIND_SQLITE,
                                path=f"{db} → session_usage",
                                detail="删除该会话的用量统计行",
                                reversible=True,
                                db_path=str(db),
                                table="session_usage",
                                key_col="session_id",
                                key_val=sid,
                            )
                        )
                except sqlite3.Error:
                    pass

            # VACUUM is what actually returns the pages to the filesystem.
            plan.actions.append(
                DeleteAction(
                    kind=KIND_SQLITE,
                    path=str(db),
                    detail="VACUUM 数据库以真正释放磁盘空间（软删除不会释放）",
                    size=safe_size(db),
                    reversible=False,
                    db_path=str(db),
                    table="__vacuum__",
                    key_col="",
                    key_val="",
                )
            )
            plan.warnings.append(
                "WorkBuddy 的对话正文不在本机，删除只清理本地会话记录与索引，释放空间很小。"
            )
        except sqlite3.Error as e:
            plan.blocked = True
            plan.block_reason = f"读取数据库失败：{e}"
        finally:
            con.close()

        live = self.is_running()
        if live:
            plan.blocked = True
            plan.block_reason = (
                f"WorkBuddy 正在运行（{', '.join(live)}）。"
                "请先完全退出 WorkBuddy，否则可能损坏数据库。"
            )
        return plan

    def iter_text(self, sid: str):
        """Metadata only: WorkBuddy stores no conversation body locally.

        Yielding the metadata still lets search find a session by its title or
        model, which is genuinely useful. It is deliberately *not* reported as
        full-text searchable content -- core.search marks this adapter as
        having no body so an empty result is never mistaken for "nothing there".
        """
        con = self._connect()
        if con is None:
            return
        try:
            if not self._has_table(con, "sessions"):
                return
            row = con.execute("select * from sessions where id = ?", (sid,)).fetchone()
            if row is None:
                return
            d = dict(row)
            title = (d.get("custom_title") or d.get("title") or "").strip()
            if title:
                yield ("system", "title", title)
            for key in ("model", "expert_id", "mode", "group_title", "cwd"):
                v = d.get(key)
                if v:
                    yield ("system", key, str(v))
        except sqlite3.Error:
            pass
        finally:
            con.close()

    # --------------------------------------------------------------- preview

    def preview(self, sid: str) -> dict:
        """Explain what *is* available for a WorkBuddy session.

        WorkBuddy keeps no conversation body locally: the `sessions` table has
        only metadata (title, timestamps, model, per-session settings) and the
        message history lives cloud-side. Rather than show a misleading empty
        transcript, this reports the metadata that does exist and says plainly
        that the content is not on this machine.
        """
        from core.model import Message

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

        con = self._connect()
        if con is None:
            out["reason"] = "无法以只读方式打开 workbuddy.db。"
            return out
        try:
            if not self._has_table(con, "sessions"):
                out["reason"] = "workbuddy.db 中没有 sessions 表，格式与预期不符。"
                return out
            row = con.execute("select * from sessions where id = ?", (sid,)).fetchone()
            if row is None:
                out["reason"] = "数据库中找不到该会话。"
                return out
            d = dict(row)
            out["title"] = (d.get("custom_title") or d.get("title") or "").strip() or "(无标题)"

            fields = [
                ("状态", d.get("status")),
                ("模式", d.get("mode")),
                ("模型", d.get("model")),
                ("来源", d.get("source_mode")),
                ("沙箱", d.get("use_sandbox_cli")),
                ("可见性", d.get("visibility")),
                ("分组", d.get("group_title")),
                ("传输", d.get("transport")),
                ("最后提问", d.get("last_user_prompt_expert_selection")),
                ("创建时间", _ms(d.get("created_at"))),
                ("更新时间", _ms(d.get("updated_at"))),
                ("最后活动", _ms(d.get("last_activity_at"))),
            ]
            lines = [f"{k}：{v}" for k, v in fields if v not in (None, "", -1)]
            body = "\n".join(lines) or "（该行没有除 id 之外的可读字段）"

            out["messages"] = [
                Message("system", body, d.get("updated_at"), "note").to_dict()
            ]
            out["total_messages"] = 1
            out["extra"] = {
                "has_local_content": False,
                "db_path": str(self.db_path()),
                "fields": {k: str(v) for k, v in d.items() if v not in (None, "")},
            }
            out["available"] = True
            out["reason"] = (
                "WorkBuddy 的对话正文保存在云端，本机数据库只有元数据，"
                "因此看不到消息内容——下面是该会话在本机的全部可用信息。"
            )
        except sqlite3.Error as e:
            out["reason"] = f"读取数据库失败：{e}"
        finally:
            con.close()
        return out

    # --------------------------------------------------------------- verify

    def verify_absent(self, sid: str) -> tuple[bool, str]:
        con = self._connect()
        if con is None:
            return False, "无法打开数据库进行校验。"
        try:
            if not self._has_table(con, "sessions"):
                return False, "sessions 表不存在。"
            n = con.execute("select count(*) from sessions where id = ?", (sid,)).fetchone()[0]
            if n:
                return False, "sessions 表中仍存在该会话行。"
            if self._has_table(con, "session_usage"):
                m = con.execute(
                    "select count(*) from session_usage where session_id = ?", (sid,)
                ).fetchone()[0]
                if m:
                    return False, "session_usage 表中仍存在该会话的统计行。"
            return True, "数据库中的会话行与统计行均已删除。"
        except sqlite3.Error as e:
            return False, f"校验时出错：{e}"
        finally:
            con.close()

    # --------------------------------------------------------------- health

    def health(self) -> list[dict]:
        findings: list[dict] = []
        con = self._connect()
        if con is None:
            return findings
        try:
            if self._has_table(con, "sessions") and self._has_column(con, "sessions", "deleted_at"):
                n = con.execute(
                    "select count(*) from sessions where deleted_at > 0"
                ).fetchone()[0]
                if n:
                    findings.append(
                        {
                            "agent": self.id,
                            "level": "warn",
                            "kind": "soft_deleted",
                            "title": f"{n} 个会话被软删除但仍在数据库中",
                            "detail": "deleted_at 已置位，但行和磁盘页面都没释放。",
                            "items": [],
                            "size": 0,
                            "action": "在本工具中永久删除可真正释放空间。",
                        }
                    )
            orphan_usage = []
            if self._has_table(con, "session_usage") and self._has_table(con, "sessions"):
                try:
                    orphan_usage = [
                        str(r[0])
                        for r in con.execute(
                            "select session_id from session_usage where session_id not in "
                            "(select id from sessions)"
                        )
                    ]
                except sqlite3.Error:
                    pass
            if orphan_usage:
                findings.append(
                    {
                        "agent": self.id,
                        "level": "info",
                        "kind": "orphan_usage",
                        "title": f"{len(orphan_usage)} 条孤立的用量记录",
                        "detail": "session_usage 中的会话已不存在。",
                        "items": orphan_usage,
                        "size": 0,
                        "action": "",
                    }
                )
        except sqlite3.Error:
            pass
        finally:
            con.close()

        # WAL sidecars left behind by an unclean shutdown.
        for suffix in ("-wal", "-shm"):
            side = Path(str(self.db_path()) + suffix)
            if side.exists() and safe_size(side) > 8 * 1024 * 1024:
                findings.append(
                    {
                        "agent": self.id,
                        "level": "info",
                        "kind": "wal",
                        "title": f"较大的数据库日志文件 {side.name}",
                        "detail": "正常退出 WorkBuddy 后通常会自动收缩。",
                        "items": [str(side)],
                        "size": safe_size(side),
                        "action": "",
                    }
                )
        return findings

    # --------------------------------------------------------- extra utilities

    def backup_db(self, dest_dir: Path) -> Path | None:
        """Consistent copy of the database using SQLite's own backup API.

        Both connections are closed explicitly -- `with sqlite3.connect(...)`
        does not close the handle, which leaves the copy locked on Windows.
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
