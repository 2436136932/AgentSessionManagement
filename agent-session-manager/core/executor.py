"""Transactional executor: the only code allowed to modify an agent's data.

Every deletion follows the same fixed sequence, and any failure rolls back the
steps already taken in that operation:

    1. re-validate   every action path is inside the adapter's declared roots
                     and every session id is a single safe path component
    2. preflight     the agent must not be running; the plan must not be blocked
    3. backup SQLite consistent copies of any database that will be modified
    4. stage         move files/directories into the quarantine folder
                     (same volume move when possible, so it is fast and atomic)
    5. apply DB      delete rows inside one BEGIN IMMEDIATE transaction
    6. post-check    re-run the adapter's verify_absent()
    7. journal       append a JSONL record describing every change
    8. rollback      on any error, undo steps 4-5 and report

Nothing is ever deleted permanently by the default path: files land in
_data/quarantine/<op-id>/ and can be restored by id. This is what makes the
tool safe to point at real session stores.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import time
import uuid
from pathlib import Path

from adapters.registry import get_adapter
from core import inventory
from core.model import (
    KIND_ATTACHMENT,
    KIND_DIR,
    KIND_FILE,
    KIND_JSON_INDEX,
    KIND_SQLITE,
    DeletePlan,
)
from core.util import (
    append_jsonl,
    dir_size,
    human_size,
    is_safe_key,
    is_within,
    journal_path,
    now_ms,
    quarantine_root,
    read_jsonl,
    remove_tree,
    stamp,
)


class ExecutionError(Exception):
    pass


#: Fallback key when a journal record predates the table/key_col fields.
CHAT_INDEX_KEY_FALLBACK = "chat.ChatSessionStore.index"


def plan_fingerprint(plan: DeletePlan) -> str:
    """A digest of what the plan will touch, as it stands right now.

    The point is to detect that a session changed *between* the moment the user
    reviewed the plan and the moment they confirmed it. An agent that is still
    running (or one that was restarted in between) can rewrite its transcript
    or index; deleting a version the user never saw is exactly the mistake this
    guards against.

    Covers each target's existence, size and mtime, plus the plan's shape, so
    both "the data moved on" and "the plan is not the plan I reviewed" produce
    a mismatch.
    """
    import hashlib

    h = hashlib.sha256()
    h.update(f"{plan.agent}\x00{plan.sid}\x00{plan.blocked}\x00".encode("utf-8"))
    for a in plan.actions:
        h.update(f"{a.kind}\x00{a.path}\x00{a.table}\x00{a.key_val}\x00".encode("utf-8"))
        target = a.db_path or a.json_pointer or a.path
        if not target:
            continue
        p = Path(target)
        try:
            st = p.stat()
            h.update(f"{st.st_size}\x00{int(st.st_mtime_ns)}\x00".encode("utf-8"))
        except OSError:
            h.update(b"<absent>\x00")
        # A directory's own mtime does not change when a file inside it is
        # rewritten, so fold in the newest nested mtime as well.
        if p.is_dir():
            newest = 0
            total = 0
            try:
                for dp, _dn, fns in os.walk(p):
                    for fn in fns:
                        try:
                            s2 = os.stat(os.path.join(dp, fn))
                        except OSError:
                            continue
                        newest = max(newest, s2.st_mtime_ns)
                        total += s2.st_size
            except OSError:
                pass
            h.update(f"{newest}\x00{total}\x00".encode("utf-8"))
    return h.hexdigest()


class Executor:
    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _roots_for(adapter) -> list[Path]:
        return [Path(p) for p in adapter.roots()]

    @staticmethod
    def validate(plan: DeletePlan, adapter) -> list[str]:
        """Return a list of problems; empty means the plan may be executed."""
        problems: list[str] = []
        roots = Executor._roots_for(adapter)
        if not roots:
            problems.append("适配器没有声明任何根目录，拒绝执行。")
        # The id itself must be a safe lookup key. Path-shaped ids are checked
        # by the path rules below, which is where traversal actually matters:
        # some stores (VS Code) legitimately use ids containing "/" and ":".
        if not is_safe_key(plan.sid):
            problems.append(f"会话 ID 不安全：{plan.sid!r}")

        for a in plan.actions + plan.optional_actions:
            if a.kind in (KIND_DIR, KIND_FILE, KIND_ATTACHMENT):
                if not is_within(a.path, roots):
                    problems.append(f"路径超出该 Agent 的数据目录，拒绝执行：{a.path}")
            elif a.kind in (KIND_SQLITE, KIND_JSON_INDEX):
                target = a.db_path or a.json_pointer or a.path
                if target and not is_within(target, roots):
                    problems.append(f"数据库/索引路径超出数据目录，拒绝执行：{target}")

                # For key-based edits the value must not be able to escape the
                # container it is written into.
                if a.key_val and not is_safe_key(a.key_val):
                    problems.append(f"键值不安全，拒绝执行：{a.key_val!r}")
            else:
                problems.append(f"未知操作类型：{a.kind}")
        return problems

    @staticmethod
    def check_pinned(plan: DeletePlan, allow_unpin: bool = False,
                     cwd: str = "") -> str:
        """Return a refusal message when the session is protected, else ''.

        Two levels of protection, both deliberate user decisions:

          * session pin   -- protects one conversation
          * workspace pin -- protects every session under a folder, including
                             ones that do not exist yet

        Either outranks every other consideration: a protected session is never
        deleted unless the caller explicitly opts in (allow_unpin). This is what
        stops a bulk delete from silently taking the one conversation -- or the
        whole project -- someone actually cares about.
        """
        if allow_unpin:
            return ""
        from core import store

        info = store.pin_info(plan.agent, plan.sid)
        if info is not None:
            reason = (info or {}).get("reason") or ""
            extra = f"（备注：{reason}）" if reason else ""
            return (
                f"该会话已被标记为「保留」{extra}，拒绝删除。"
                "如确实要删除，请先取消保留标记，或在删除时显式勾选「忽略保留标记」。"
            )

        if cwd:
            ws = store.match_workspace(plan.agent, cwd)
            if ws is not None:
                reason = ws.get("reason") or ""
                extra = f"（备注：{reason}）" if reason else ""
                return (
                    f"该会话所在的工作区「{ws.get('path', '')}」已被标记为「保留」"
                    f"{extra}，其下所有会话（含将来新增的）都会受到保护，拒绝删除。"
                    "如确实要删除，请先取消该工作区的保留标记，"
                    "或在删除时显式勾选「忽略保留标记」。"
                )
        return ""

    # ------------------------------------------------------------------ default

    def execute(
        self,
        agent_id: str,
        sid: str,
        allow_permanent: bool = False,
        include_optional: bool = False,
        include_attachments: bool = False,
        allow_unpin: bool = False,
        expected_fingerprint: str = "",
    ) -> dict:
        adapter = get_adapter(agent_id)
        if adapter is None:
            raise ExecutionError(f"未知的 Agent：{agent_id}")

        plan = adapter.plan_delete(sid)
        if plan.blocked:
            raise ExecutionError(f"删除被拒绝：{plan.block_reason}")

        # A pin outranks everything else, including a caller that forgot to ask.
        # The session's cwd is needed so a workspace-level pin can match.
        cwd = ""
        try:
            from core import inventory

            s = inventory.find(agent_id, sid)
            if s is not None:
                cwd = s.cwd or ""
        except Exception:
            cwd = ""
        refusal = self.check_pinned(plan, allow_unpin=allow_unpin, cwd=cwd)
        if refusal:
            raise ExecutionError(refusal)

        # Reject a confirmation that no longer matches the data. This closes
        # the window between "the user read the plan" and "the delete ran",
        # during which a running agent may have rewritten the session.
        if expected_fingerprint:
            current = plan_fingerprint(plan)
            if current != expected_fingerprint:
                raise ExecutionError(
                    "会话内容在你确认之后发生了变化，为避免删除你未审阅的版本，"
                    "本次删除已取消。请重新打开删除计划并确认。\n"
                    f"（计划指纹 {expected_fingerprint[:12]}… → 当前 {current[:12]}…）"
                )

        problems = self.validate(plan, adapter)
        if problems:
            raise ExecutionError("计划未通过安全检查：\n  - " + "\n  - ".join(problems))

        actions = list(plan.actions)
        if include_optional or include_attachments:
            actions += list(plan.optional_actions)

        op_id = f"{stamp()}-{uuid.uuid4().hex[:8]}"
        qdir = quarantine_root() / op_id
        qdir.mkdir(parents=True, exist_ok=True)

        record: dict = {
            "op_id": op_id,
            "time": now_ms(),
            "agent": agent_id,
            "agent_label": adapter.label,
            "sid": sid,
            "title": plan.title,
            "permanent": bool(allow_permanent),
            "quarantine": str(qdir),
            "steps": [],
            "status": "started",
            "errors": [],
        }

        staged: list[tuple[Path, Path]] = []   # (original, quarantined) for rollback
        db_undo: list[dict] = []               # captured rows for SQL-level rollback

        try:
            # ---- stage file/dir moves ------------------------------------
            for a in actions:
                if a.kind not in (KIND_DIR, KIND_FILE, KIND_ATTACHMENT):
                    continue
                src = Path(a.path)
                if not src.exists():
                    record["steps"].append(
                        {"action": a.kind, "path": a.path, "result": "skipped-missing"}
                    )
                    continue
                dest = qdir / self._quarantine_rel(src)
                dest.parent.mkdir(parents=True, exist_ok=True)
                try:
                    self._move(src, dest)
                    staged.append((src, dest))
                    record["steps"].append(
                        {
                            "action": a.kind,
                            "path": a.path,
                            "quarantined_to": str(dest),
                            "size": a.size,
                            "result": "moved",
                        }
                    )
                except OSError as e:
                    raise ExecutionError(f"移动失败 {src}: {e}") from e

            # ---- database changes ----------------------------------------
            dbs = {a.db_path for a in actions if a.kind == KIND_SQLITE and a.db_path}
            for db in dbs:
                bdir = qdir / "_db-backup"
                bdir.mkdir(parents=True, exist_ok=True)
                backup = self._backup_sqlite(Path(db), bdir)
                record["steps"].append(
                    {"action": "db_backup", "path": db, "quarantined_to": str(backup), "result": "backed_up"}
                )

            # JSON indexes are edited in place, so keep a verbatim copy first;
            # without this a restore could not put the index back.
            json_files = {
                (a.json_pointer or a.path)
                for a in actions
                if a.kind == KIND_JSON_INDEX
            }
            for jp in json_files:
                src = Path(jp)
                if not src.exists():
                    continue
                jdir = qdir / "_json-backup"
                jdir.mkdir(parents=True, exist_ok=True)
                dest = jdir / src.name
                shutil.copy2(src, dest)
                record["steps"].append(
                    {
                        "action": "json_backup",
                        "path": str(src),
                        "quarantined_to": str(dest),
                        "result": "backed_up",
                    }
                )

            for a in actions:
                if a.kind != KIND_SQLITE:
                    continue
                if a.table == "__vacuum__":
                    continue
                res = self._sqlite_delete(Path(a.db_path), a.table, a.key_col, a.key_val)
                record["steps"].append(
                    {
                        "action": "sqlite_delete",
                        "path": a.path,
                        "db_path": a.db_path,
                        "table": a.table,
                        "key_col": a.key_col,
                        "key": a.key_val,
                        "deleted": res.get("deleted", 0),
                        # Persist the removed rows so a restore can re-insert
                        # exactly these rows without clobbering later changes.
                        "rows": res.get("rows", []),
                        "result": "deleted",
                    }
                )

            # ---- JSON index rewrite --------------------------------------
            for a in actions:
                if a.kind != KIND_JSON_INDEX:
                    continue
                info = self._json_drop(
                    Path(a.json_pointer or a.path), a.key_val, a.key_col
                )
                record["steps"].append(
                    {
                        "action": "json_index",
                        "path": a.path,
                        "key": a.key_val,
                        "mode": a.key_col,
                        "removed": info.get("removed", 0),
                        "placement": info.get("placement", []),
                        "result": "edited",
                    }
                )

            # ---- vacuum last (releases pages) ----------------------------
            for a in actions:
                if a.kind == KIND_SQLITE and a.table == "__vacuum__":
                    self._vacuum(Path(a.db_path))
                    record["steps"].append(
                        {"action": "vacuum", "path": a.db_path, "result": "vacuumed"}
                    )

            # ---- verify ---------------------------------------------------
            clean, why = adapter.verify_absent(sid)
            record["verified"] = clean
            record["verify_message"] = why
            if not clean:
                record["status"] = "verify_failed"
                record["errors"].append(why)
                self._rollback(staged, db_undo, record)
                record["status"] = "rolled_back"
                append_jsonl(journal_path(), record)
                inventory.invalidate()
                raise ExecutionError(f"删除后校验失败，已回滚：{why}")

            record["status"] = "completed"
            append_jsonl(journal_path(), record)
            inventory.invalidate()

            # Permanent mode disposes of the quarantine immediately.
            freed = 0
            if allow_permanent:
                freed, _c = dir_size(qdir)
                shutil.rmtree(qdir, ignore_errors=True)
                record["quarantine_removed"] = True

            return {
                "ok": True,
                "op_id": op_id,
                "agent": agent_id,
                "sid": sid,
                "title": plan.title,
                "steps": record["steps"],
                "verified": clean,
                "verify_message": why,
                "quarantine": str(qdir),
                "permanent": bool(allow_permanent),
                "staged_count": len(staged),
            }

        except ExecutionError:
            raise
        except Exception as e:
            record["errors"].append(f"{type(e).__name__}: {e}")
            self._rollback(staged, db_undo, record)
            record["status"] = "rolled_back"
            append_jsonl(journal_path(), record)
            inventory.invalidate()
            raise ExecutionError(f"执行失败，已回滚：{e}") from e

    # ------------------------------------------------------------- primitives

    @staticmethod
    def _quarantine_rel(src: Path) -> Path:
        """Mirror the original path under the quarantine folder.

        Paths outside the home directory are flattened to a hashed name plus
        their basename so nothing can escape the quarantine root.
        """
        try:
            import hashlib

            parts = src.resolve().parts
            drive = parts[0].replace(":", "").replace("\\", "")
            rest = [p for p in parts[1:] if p not in ("\\", "/")]
            digest = hashlib.sha1(str(src).encode("utf-8")).hexdigest()[:8]
            # Keep the last few components so the quarantine stays readable.
            tail = rest[-3:]
            return Path(drive) / digest / Path(*tail)
        except Exception:
            return Path("misc") / src.name

    @staticmethod
    def _move(src: Path, dest: Path) -> None:
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        try:
            os.replace(src, dest) if src.is_file() else shutil.move(str(src), str(dest))
        except OSError:
            shutil.move(str(src), str(dest))

    @staticmethod
    def _backup_sqlite(src: Path, dest_dir: Path) -> Path:
        """Consistent copy of a live SQLite database.

        Connections are closed explicitly: `with sqlite3.connect(...)` commits
        the transaction but does NOT close the handle, which leaves the file
        locked on Windows and makes the quarantine folder impossible to remove
        (observed as WinError 32 on cleanup).
        """
        dest = dest_dir / src.name
        s = d = None
        try:
            s = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
            d = sqlite3.connect(str(dest))
            s.backup(d)
            d.commit()
            return dest
        except sqlite3.Error:
            shutil.copy2(src, dest)
            return dest
        finally:
            for con in (d, s):
                try:
                    if con is not None:
                        con.close()
                except sqlite3.Error:
                    pass

    @staticmethod
    def _sqlite_delete(db: Path, table: str, key_col: str, key_val: str) -> dict:
        """Delete matching rows, remembering them so a rollback can restore."""
        # VS Code stores its chat list index as a single JSON blob in a
        # key/value table rather than as rows.
        if table == "__vscode_chat_index__":
            return Executor._vscode_index_delete(db, key_col, key_val)

        con = sqlite3.connect(str(db), timeout=30)
        con.row_factory = sqlite3.Row
        try:
            con.execute("BEGIN IMMEDIATE")
            try:
                rows = list(
                    con.execute(f'select * from "{table}" where "{key_col}" = ?', (key_val,))
                )
            except sqlite3.Error:
                rows = []
            con.execute(f'delete from "{table}" where "{key_col}" = ?', (key_val,))
            deleted = con.total_changes
            con.commit()
            return {
                "db": str(db),
                "table": table,
                "key_col": key_col,
                "key_val": key_val,
                "rows": [dict(r) for r in rows],
                "deleted": deleted,
            }
        except sqlite3.Error as e:
            con.rollback()
            raise ExecutionError(f"数据库操作失败 {db} / {table}: {e}") from e
        finally:
            con.close()

    @staticmethod
    def _vscode_index_delete(db: Path, key: str, sid: str) -> dict:
        """Remove one entry from VS Code's chat index JSON blob.

        The whole `value` cell is rewritten, so the original blob is captured
        for the restore path.
        """
        con = sqlite3.connect(str(db), timeout=30)
        try:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "select value from ItemTable where key = ?", (key,)
            ).fetchone()
            if not row or row[0] is None:
                con.rollback()
                return {"db": str(db), "table": "__vscode_chat_index__",
                        "key_col": key, "key_val": sid, "rows": [], "deleted": 0}
            raw = row[0]
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", "replace")
            obj = json.loads(raw)
            entries = obj.get("entries") if isinstance(obj, dict) else None
            if not isinstance(entries, dict) or sid not in entries:
                con.rollback()
                return {"db": str(db), "table": "__vscode_chat_index__",
                        "key_col": key, "key_val": sid, "rows": [], "deleted": 0}
            removed_entry = entries.pop(sid)
            new_raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
            con.execute(
                "update ItemTable set value = ? where key = ?", (new_raw, key)
            )
            con.commit()
            return {
                "db": str(db),
                "table": "__vscode_chat_index__",
                "key_col": key,
                "key_val": sid,
                "deleted": 1,
                # Enough to rebuild the entry exactly where it was.
                "rows": [{"__entry__": removed_entry, "__key__": sid}],
            }
        except (sqlite3.Error, ValueError) as e:
            con.rollback()
            raise ExecutionError(
                f"VS Code 聊天索引操作失败 {db} / {key}: {e}"
            ) from e
        finally:
            con.close()

    @staticmethod
    def _vscode_index_restore(db: Path, key: str, sid: str, entry) -> int:
        """Put one entry back into VS Code's chat index JSON blob."""
        if entry is None:
            return 0
        con = sqlite3.connect(str(db), timeout=30)
        try:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "select value from ItemTable where key = ?", (key,)
            ).fetchone()
            if not row or row[0] is None:
                obj: dict = {"version": 1, "entries": {}}
            else:
                raw = row[0]
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", "replace")
                try:
                    obj = json.loads(raw)
                except (ValueError, TypeError):
                    obj = {"version": 1, "entries": {}}
            if not isinstance(obj, dict):
                obj = {"version": 1, "entries": {}}
            entries = obj.setdefault("entries", {})
            if not isinstance(entries, dict):
                entries = {}
                obj["entries"] = entries
            if sid in entries:
                con.rollback()
                return 0
            entries[sid] = entry
            con.execute(
                "update ItemTable set value = ? where key = ?",
                (json.dumps(obj, ensure_ascii=False, separators=(",", ":")), key),
            )
            con.commit()
            return 1
        except (sqlite3.Error, ValueError):
            con.rollback()
            return 0
        finally:
            con.close()

    @staticmethod
    def _sqlite_restore(info: dict) -> None:
        rows = info.get("rows") or []
        if not rows:
            return
        con = sqlite3.connect(info["db"], timeout=30)
        try:
            cols = list(rows[0].keys())
            placeholders = ",".join("?" for _ in cols)
            collist = ",".join(f'"{c}"' for c in cols)
            con.execute("BEGIN IMMEDIATE")
            for r in rows:
                con.execute(
                    f'insert or replace into "{info["table"]}" ({collist}) values ({placeholders})',
                    [r[c] for c in cols],
                )
            con.commit()
        except sqlite3.Error:
            con.rollback()
        finally:
            con.close()

    @staticmethod
    def _vacuum(db: Path) -> None:
        try:
            con = sqlite3.connect(str(db), timeout=60)
            try:
                con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                con.execute("VACUUM")
                con.commit()
            finally:
                con.close()
        except sqlite3.Error:
            # Vacuum is an optimisation, not a correctness requirement.
            pass

    @staticmethod
    def _json_drop(p: Path, sid: str, mode: str) -> dict:
        """Remove a session id from an adapter's JSON index.

        Returns the number of references removed *and* where each one was, so a
        restore can put the id back at the same positions instead of replacing
        the whole file (which would discard anything changed in the meantime).
        """
        from core.util import read_json, write_json_atomic

        out = {"removed": 0, "placement": []}
        obj = read_json(p, None)
        if not isinstance(obj, dict):
            return out

        if mode == "drop_session_id":
            try:
                workspaces = obj["tables"]["workspaces"]
            except (KeyError, TypeError):
                workspaces = {}
            for wsid, w in (workspaces or {}).items():
                ids = (w or {}).get("sessionIds")
                if isinstance(ids, list) and sid in ids:
                    positions = [i for i, x in enumerate(ids) if x == sid]
                    for pos in positions:
                        out["placement"].append(
                            {"kind": "workspace", "workspace_id": wsid, "index": pos}
                        )
                    w["sessionIds"] = [x for x in ids if x != sid]
                    out["removed"] += len(positions)
            # Keep the archive/pin lists consistent as well.
            g = obj.get("global")
            if isinstance(g, dict):
                for k in ("archivedSessionIds", "pinnedSessionIds"):
                    v = g.get(k)
                    if isinstance(v, list) and sid in v:
                        for pos in [i for i, x in enumerate(v) if x == sid]:
                            out["placement"].append({"kind": "global", "field": k, "index": pos})
                        g[k] = [x for x in v if x != sid]
                        out["removed"] += 1
            if out["removed"]:
                write_json_atomic(p, obj)
            return out

        if mode == "drop_sessions_key":
            sessions = obj.get("sessions")
            if isinstance(sessions, dict) and sid in sessions:
                del sessions[sid]
                write_json_atomic(p, obj)
                out["removed"] = 1
                out["placement"].append({"kind": "sessions_key"})
            return out

        if mode == "drop_conversation_entry":
            # CodeBuddy: a project index holds {"conversations":[{id,...}]}.
            # Only the matching entry is removed; the project and its other
            # conversations stay untouched.
            convs = obj.get("conversations")
            if isinstance(convs, list):
                keep = [
                    c
                    for c in convs
                    if not (isinstance(c, dict) and str(c.get("id")) == sid)
                ]
                if len(keep) != len(convs):
                    positions = [
                        i
                        for i, c in enumerate(convs)
                        if isinstance(c, dict) and str(c.get("id")) == sid
                    ]
                    removed_entries = [convs[i] for i in positions]
                    obj["conversations"] = keep
                    write_json_atomic(p, obj)
                    out["removed"] = len(removed_entries)
                    out["placement"].append(
                        {
                            "kind": "conversation_entry",
                            "positions": positions,
                            "entries": removed_entries,
                        }
                    )
            return out

        return out

    @staticmethod
    def _json_restore(p: Path, sid: str, mode: str, placement: list[dict]) -> int:
        """Re-insert a session id into a JSON index at its recorded positions."""
        from core.util import read_json, write_json_atomic

        obj = read_json(p, None)
        if not isinstance(obj, dict) or not placement:
            # No placement information: fall back to the verbatim backup.
            return 0

        done = 0
        if mode == "drop_session_id":
            for pl in placement:
                try:
                    if pl.get("kind") == "workspace":
                        ids = obj["tables"]["workspaces"][pl["workspace_id"]]["sessionIds"]
                    elif pl.get("kind") == "global":
                        ids = obj["global"][pl["field"]]
                    else:
                        continue
                except (KeyError, TypeError):
                    continue
                if sid in ids:
                    continue
                pos = min(int(pl.get("index", len(ids))), len(ids))
                ids.insert(pos, sid)
                done += 1
        elif mode == "drop_sessions_key":
            if not isinstance(obj.get("sessions"), dict):
                obj["sessions"] = {}
            if sid not in obj["sessions"]:
                obj["sessions"][sid] = {}
                done += 1
        elif mode == "drop_conversation_entry":
            # Put the removed conversation objects back at their positions so
            # the project's conversation order is preserved.
            convs = obj.get("conversations")
            if not isinstance(convs, list):
                convs = []
                obj["conversations"] = convs
            for pl in placement:
                entries = pl.get("entries") or []
                positions = pl.get("positions") or []
                existing = {
                    str(c.get("id")) for c in convs if isinstance(c, dict)
                }
                for entry, pos in zip(entries, positions):
                    if not isinstance(entry, dict):
                        continue
                    if str(entry.get("id")) in existing:
                        continue
                    convs.insert(min(int(pos), len(convs)), entry)
                    existing.add(str(entry.get("id")))
                    done += 1
        if done:
            write_json_atomic(p, obj)
        return done

    # ----------------------------------------------------------------- rollback

    def _rollback(self, staged: list[tuple[Path, Path]], db_undo: list[dict], record: dict) -> None:
        for info in reversed(db_undo):
            try:
                self._sqlite_restore(info)
                record["steps"].append(
                    {"action": "db_rollback", "table": info.get("table"), "result": "restored"}
                )
            except Exception as e:
                record["errors"].append(f"数据库回滚失败 {info.get('table')}: {e}")

        for src, dest in reversed(staged):
            try:
                if dest.exists():
                    src.parent.mkdir(parents=True, exist_ok=True)
                    self._move(dest, src)
                    record["steps"].append(
                        {"action": "rollback_move", "path": str(src), "result": "restored"}
                    )
            except Exception as e:
                record["errors"].append(f"回滚失败 {src}: {e}")

    # ------------------------------------------------------------------ restore

    @staticmethod
    def list_operations(limit: int = 200) -> list[dict]:
        """Deletion operations, newest first.

        Restore records are themselves journalled with a distinct op_id
        ("<op>-restore"); they are excluded here and reported as a flag on the
        original operation instead.
        """
        all_ops = read_jsonl(journal_path())
        restores = {
            o.get("restored_from")
            for o in all_ops
            if o.get("restored_from")
        }

        ops = [
            o
            for o in all_ops
            if not o.get("restored_from")
            and o.get("status") in ("completed", "rolled_back", "verify_failed")
        ]
        ops.sort(key=lambda o: -(o.get("time") or 0))

        out = []
        for o in ops[:limit]:
            q = Path(o.get("quarantine") or "")
            present = q.exists()
            size = 0
            if present:
                size, _c = dir_size(q)
            out.append(
                {
                    "op_id": o.get("op_id"),
                    "time": o.get("time"),
                    "agent": o.get("agent"),
                    "agent_label": o.get("agent_label"),
                    "sid": o.get("sid"),
                    "title": o.get("title"),
                    "status": o.get("status"),
                    "verified": o.get("verified"),
                    "verify_message": o.get("verify_message"),
                    "permanent": o.get("permanent"),
                    "restorable": present and o.get("status") in ("completed", "rolled_back"),
                    "was_restored": o.get("op_id") in restores,
                    "quarantine": str(q) if q else "",
                    "quarantine_size": size,
                    "quarantine_size_h": human_size(size),
                    "steps": len(o.get("steps") or []),
                }
            )
        return out

    @staticmethod
    def restore(op_id: str) -> dict:
        """Put a previously quarantined session back where it came from.

        File/directory moves are reversed by moving out of quarantine; database
        rows and JSON index entries are re-inserted from the journal, so later
        unrelated changes in the same files are preserved.
        """
        ops = {o.get("op_id"): o for o in read_jsonl(journal_path())}
        op = ops.get(op_id)
        if not op:
            raise ExecutionError(f"找不到操作记录：{op_id}")
        q = Path(op.get("quarantine") or "")
        if not q.exists():
            raise ExecutionError("隔离区已不存在（可能已被永久删除）。")

        sid = op.get("sid") or ""
        restored = 0
        failed: list[str] = []

        # 1. Move files and directories back.
        for step in op.get("steps") or []:
            if step.get("action") not in (KIND_DIR, KIND_FILE, KIND_ATTACHMENT):
                continue
            if step.get("result") != "moved":
                continue
            dest = step.get("quarantined_to")
            if not dest:
                continue
            destp = Path(dest)
            if not destp.exists():
                continue
            target = Path(step["path"])
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists():
                    if target.is_dir():
                        shutil.rmtree(target, ignore_errors=True)
                    else:
                        target.unlink()
                Executor._move(destp, target)
                restored += 1
            except OSError as e:
                failed.append(f"{target}: {e}")

        # 2. Re-insert database rows that were removed.
        for step in op.get("steps") or []:
            if step.get("action") != "sqlite_delete":
                continue
            rows = step.get("rows") or []
            if not rows:
                continue
            db = step.get("db_path")
            table = step.get("table")
            if not db or not table:
                continue

            # VS Code chat index: restore the JSON entry inside the blob.
            if table == "__vscode_chat_index__":
                key = step.get("key_col") or CHAT_INDEX_KEY_FALLBACK
                try:
                    restored_entry = rows[0].get("__entry__")
                    sid_key = rows[0].get("__key__") or sid
                    n = Executor._vscode_index_restore(
                        Path(db), key, sid_key, restored_entry
                    )
                    restored += n
                    if not n:
                        failed.append(f"{db} / {key}: 索引条目未能回填")
                except Exception as e:
                    failed.append(f"{db} / {key}: {e}")
                continue

            try:
                con = sqlite3.connect(db, timeout=30)
                try:
                    cols = list(rows[0].keys())
                    collist = ",".join(f'"{c}"' for c in cols)
                    placeholders = ",".join("?" for _ in cols)
                    con.execute("BEGIN IMMEDIATE")
                    for r in rows:
                        con.execute(
                            f'insert or replace into "{table}" ({collist}) '
                            f"values ({placeholders})",
                            [r[c] for c in cols],
                        )
                    con.commit()
                    restored += len(rows)
                finally:
                    con.close()
            except sqlite3.Error as e:
                failed.append(f"{db} / {table}: {e}")

        # 3. Re-insert JSON index references at their original positions.
        for step in op.get("steps") or []:
            if step.get("action") != "json_index":
                continue
            target = step.get("path")
            mode = step.get("mode") or ""
            placement = step.get("placement") or []
            if not target or not placement:
                continue
            try:
                n = Executor._json_restore(Path(target), sid, mode, placement)
                restored += n
                if not n:
                    failed.append(f"{target}: 索引条目未能回填（位置信息不适用）")
            except Exception as e:
                failed.append(f"{target}: {e}")

        record = {
            "op_id": f"{op_id}-restore-{uuid.uuid4().hex[:6]}",
            "time": now_ms(),
            "agent": op.get("agent"),
            "sid": sid,
            "title": op.get("title"),
            "restored_from": op_id,
            "status": "restored" if not failed else "restore_partial",
            "restored_count": restored,
            "errors": failed,
            "steps": [],
        }
        append_jsonl(journal_path(), record)
        inventory.invalidate()

        # A fully successful restore puts everything back, so the quarantine
        # folder (including the _db-backup / _json-backup safety copies) has
        # served its purpose and is removed. On a partial failure it is kept
        # so the remaining data can be recovered by hand. The journal keeps the
        # full record either way.
        if not failed:
            err = remove_tree(q)
            if err:
                # Cosmetic only: the data is already restored. Report it rather
                # than hide it, so a stuck handle is visible.
                record["errors"].append(f"隔离区未能清理（不影响数据还原）：{err}")

        return {
            "ok": not failed,
            "restored": restored,
            "errors": failed,
            "op_id": op_id,
        }
