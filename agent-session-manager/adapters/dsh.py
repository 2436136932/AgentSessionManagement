"""DeepSeek Harness (DSH) adapter.

A DSH conversation is spread over four locations, which is exactly why manual
cleanup leaves residue:

  1. ~/.dsh/sessions/<workspace-slug>/<sid>/session.v4.jsonl.zstd   (content)
  2. ~/.dsh/storages/session_projcache/sessions/<sid>.json          (metadata:
     title, first prompt, goal, sandbox mode -- drives the sidebar entry)
  3. ~/.dsh/storages/workspace.json                                  (workspace ->
     sessionIds arrays; a stale id here is what makes a session "come back")
  4. ~/.dsh/attachments/v1/objects/<aa>/<sha256>                     (content
     addressed blobs, SHARED between sessions -- never deleted blindly)

Deleting (1) alone leaves a ghost entry in the sidebar (proved on this machine:
session-2aad195e-ba28-4ef3-a074-f0edbb85eef2 has metadata but no content).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from adapters.base import Adapter
from core.model import (
    KIND_ATTACHMENT,
    KIND_DIR,
    KIND_FILE,
    KIND_JSON_INDEX,
    DeleteAction,
    DeletePlan,
    Session,
)
from core.util import (
    dir_size,
    home,
    is_safe_session_id,
    list_dirs,
    list_files,
    now_ms,
    read_json,
    safe_size,
)


class DshAdapter(Adapter):
    id = "dsh"
    label = "DeepSeek Harness"
    processes = ("deepseek harness.exe", "dsh.exe")
    can_delete = True
    storage_hint = "~/.dsh"

    # Sessions touched more recently than this are treated as live.
    LIVE_WINDOW_MS = 10 * 60 * 1000

    # ------------------------------------------------------------------ paths

    def base(self) -> Path:
        return home() / ".dsh"

    def sessions_dir(self) -> Path:
        return self.base() / "sessions"

    def projcache_dir(self) -> Path:
        return self.base() / "storages" / "session_projcache" / "sessions"

    def workspace_json(self) -> Path:
        return self.base() / "storages" / "workspace.json"

    def attachments_dir(self) -> Path:
        return self.base() / "attachments" / "v1" / "objects"

    def roots(self) -> list[Path]:
        return [self.base()]

    def detect(self) -> bool:
        return self.sessions_dir().exists() or self.projcache_dir().exists()

    # ------------------------------------------------------------------- scan

    def _read_index(self) -> tuple[dict[str, dict], dict[str, list[str]]]:
        """Return (sid -> projcache record, sid -> [workspace ids])."""
        cache: dict[str, dict] = {}
        for f in list_files(self.projcache_dir(), ".json"):
            obj = read_json(f, None)
            if isinstance(obj, dict):
                cache[f.stem] = obj

        ws_map: dict[str, list[str]] = {}
        ws = read_json(self.workspace_json(), None)
        try:
            workspaces = ws["tables"]["workspaces"]
        except (TypeError, KeyError):
            workspaces = {}
        for wsid, w in (workspaces or {}).items():
            for sid in (w or {}).get("sessionIds") or []:
                ws_map.setdefault(sid, []).append(wsid)
        return cache, ws_map

    @staticmethod
    def _title_from(rec: dict) -> str:
        try:
            rows = rec["record"]["rows"]
        except (TypeError, KeyError):
            return ""
        t = (rows.get("title") or {}).get("val")
        if isinstance(t, str) and t.strip():
            return t.strip()
        try:
            first = rows["titleInput"]["val"]["first"]["text"]
            if isinstance(first, str):
                return first.strip().replace("\n", " ")[:120]
        except (TypeError, KeyError):
            pass
        return ""

    @staticmethod
    def _identity_from(rec: dict) -> tuple[str, int | None]:
        try:
            ident = rec["record"]["identity"]
            return str(ident.get("cwd") or ""), ident.get("createdAt")
        except (TypeError, KeyError):
            return "", None

    def list_sessions(self) -> list[Session]:
        cache, ws_map = self._read_index()
        out: list[Session] = []
        seen: set[str] = set()

        # Everything that has content on disk.
        for wsdir in list_dirs(self.sessions_dir()):
            for sdir in list_dirs(wsdir):
                sid = sdir.name
                if not is_safe_session_id(sid):
                    continue
                seen.add(sid)
                rec = cache.get(sid) or {}
                cwd, created = self._identity_from(rec)
                title = self._title_from(rec)
                size, files = dir_size(sdir)
                pc = self.projcache_dir() / f"{sid}.json"
                pc_size = safe_size(pc)
                size += pc_size
                if pc_size:
                    files += 1
                updated = self._newest_mtime(sdir, pc)
                out.append(
                    Session(
                        agent=self.id,
                        agent_label=self.label,
                        sid=sid,
                        title=title or "(无标题)",
                        cwd=cwd,
                        created_at=created,
                        updated_at=updated,
                        size=size,
                        file_count=files,
                        paths=[str(sdir)] + ([str(pc)] if pc.exists() else []),
                        is_orphan=self._is_orphan(sid, ws_map),
                        note=self._child_note(sid),
                        extra={"workspaces": ws_map.get(sid, [])},
                    )
                )

        # Index entries with no content on disk -> ghosts.
        for sid, rec in cache.items():
            if sid in seen or not is_safe_session_id(sid):
                continue
            cwd, created = self._identity_from(rec)
            pc = self.projcache_dir() / f"{sid}.json"
            out.append(
                Session(
                    agent=self.id,
                    agent_label=self.label,
                    sid=sid,
                    title=(self._title_from(rec) or "(残留索引)"),
                    cwd=cwd,
                    created_at=created,
                    updated_at=self._newest_mtime(pc),
                    size=safe_size(pc),
                    file_count=1,
                    paths=[str(pc)],
                    is_ghost=True,
                    extra={"workspaces": ws_map.get(sid, [])},
                )
            )

        out.sort(key=lambda s: (s.is_ghost, -(s.updated_at or 0)))
        return out

    @staticmethod
    def _newest_mtime(*paths: Path) -> int | None:
        """Newest modification time among these paths.

        For a directory this descends into it. That matters for correctness of
        the live-session guard: DSH appends to session.v4.jsonl.zstd, which
        updates the *file's* mtime but not the parent directory's, so looking
        only at the directory would miss a session that is being written right
        now.
        """
        best = 0.0
        for p in paths:
            try:
                st = p.stat()
            except OSError:
                continue
            if p.is_dir():
                try:
                    for dirpath, _dirnames, filenames in os.walk(p):
                        for fn in filenames:
                            try:
                                best = max(
                                    best,
                                    os.stat(os.path.join(dirpath, fn)).st_mtime,
                                )
                            except OSError:
                                continue
                except OSError:
                    best = max(best, st.st_mtime)
            else:
                best = max(best, st.st_mtime)
        return int(best * 1000) if best else None

    @staticmethod
    def _is_orphan(sid: str, ws_map: dict[str, list[str]]) -> bool:
        """A top-level session id absent from workspace.json is an orphan.

        Child/subagent sessions (no 'session-' prefix) are intentionally not
        listed in workspace.json, so they are not orphans.
        """
        if not sid.startswith("session-"):
            return False
        return sid not in ws_map

    @staticmethod
    def _child_note(sid: str) -> str:
        if not sid.startswith("session-"):
            return "子代理会话（由父会话派生）"
        return ""

    # --------------------------------------------------------------- deletion

    def _find_session_dir(self, sid: str) -> Path | None:
        for wsdir in list_dirs(self.sessions_dir()):
            cand = wsdir / sid
            if cand.is_dir():
                return cand
        return None

    def plan_delete(self, sid: str) -> DeletePlan:
        plan = self._plan(sid)
        if not is_safe_session_id(sid):
            plan.blocked = True
            plan.block_reason = f"非法会话 ID：{sid!r}"
            return plan

        sdir = self._find_session_dir(sid)
        pc = self.projcache_dir() / f"{sid}.json"
        wsjson = self.workspace_json()

        cache, ws_map = self._read_index()
        if sdir is None and sid not in cache:
            plan.blocked = True
            plan.block_reason = "磁盘与索引中都找不到该会话。"
            return plan

        # A readable title for the confirmation dialog.
        rec = cache.get(sid) or {}
        plan.title = self._title_from(rec) or (
            "(残留索引)" if sdir is None else "(无标题)"
        )

        # Content directory.
        if sdir is not None:
            size, files = dir_size(sdir)
            plan.actions.append(
                DeleteAction(
                    kind=KIND_DIR,
                    path=str(sdir),
                    detail=f"会话正文目录（{files} 个文件）",
                    size=size,
                    reversible=True,
                )
            )
            mtime = self._newest_mtime(sdir)
        else:
            mtime = self._newest_mtime(pc)
            plan.warnings.append("正文目录已不存在，只会清理残留索引（幽灵条目）。")

        # Metadata sidecar -- this is the entry the sidebar reads.
        if pc.exists():
            plan.actions.append(
                DeleteAction(
                    kind=KIND_FILE,
                    path=str(pc),
                    detail="会话元数据（侧边栏标题/首条提问）",
                    size=safe_size(pc),
                    reversible=True,
                )
            )
        else:
            plan.warnings.append("未找到元数据缓存文件。")

        # Workspace index references.
        if sid in ws_map:
            plan.actions.append(
                DeleteAction(
                    kind=KIND_JSON_INDEX,
                    path=str(wsjson),
                    detail=f"从 workspace.json 的 sessionIds 移除（{len(ws_map[sid])} 处）",
                    size=safe_size(wsjson),
                    reversible=True,
                    json_pointer=str(wsjson),
                    key_val=sid,
                    key_col="drop_session_id",
                )
            )
        else:
            plan.warnings.append("workspace.json 中没有该会话的引用（无需清理索引）。")

        # Live-session protection.
        live = self.is_running()
        recent = mtime is not None and (now_ms() - mtime) < self.LIVE_WINDOW_MS
        if recent:
            plan.warnings.append(
                "该会话在最近 10 分钟内被写入，可能正在运行中；请确认它没有被打开。"
            )
        if live and recent:
            plan.blocked = True
            plan.block_reason = (
                "DeepSeek Harness 正在运行，且该会话刚刚被写入。"
                "请先关闭 DSH（或至少关闭该会话）后再删除。"
            )

        plan.optional_actions = self._attachment_actions(sid)
        return plan

    def _attachment_actions(self, sid: str) -> list[DeleteAction]:
        """Blobs that would become unreferenced if this session were removed.

        Reference detection is a plain substring search of the blob's sha256
        over every *other* session's decompressed content -- format-agnostic
        and safe: a blob is only ever offered when no other session mentions
        it. Always optional, never part of the default plan.
        """
        adir = self.attachments_dir()
        if not adir.exists():
            return []
        blobs = [p for p in adir.glob("*/*") if p.is_file()]
        if not blobs:
            return []

        try:
            others = self._all_content_text(exclude_sid=sid)
        except Exception:
            return []
        if others is None:
            return []

        actions: list[DeleteAction] = []
        for b in blobs:
            try:
                if b.name.lower() in others:
                    continue
            except Exception:
                continue
            actions.append(
                DeleteAction(
                    kind=KIND_ATTACHMENT,
                    path=str(b),
                    detail="未被任何剩余会话引用的附件（内容寻址）",
                    size=safe_size(b),
                    reversible=True,
                )
            )
        return actions

    def _all_content_text(self, exclude_sid: str | None = None) -> str | None:
        from compression import zstd

        chunks: list[str] = []
        total = 0
        for wsdir in list_dirs(self.sessions_dir()):
            for sdir in list_dirs(wsdir):
                if exclude_sid and sdir.name == exclude_sid:
                    continue
                f = sdir / "session.v4.jsonl.zstd"
                if not f.exists():
                    continue
                total += safe_size(f)
                if total > 400 * 1024 * 1024:
                    # Too large to scan safely; skip attachment GC entirely.
                    return None
                try:
                    chunks.append(zstd.decompress(f.read_bytes()).decode("utf-8", "replace"))
                except Exception:
                    continue
        return "\n".join(chunks).lower()

    def _read_events(self, sid: str):
        """Yield parsed events from a session's transcript, or nothing.

        Shared by preview() and iter_text(). Returns an empty iterator when the
        session has no readable body (a ghost, or a corrupt archive).
        """
        if not is_safe_session_id(sid):
            return
        sdir = self._find_session_dir(sid)
        if sdir is None:
            return
        f = sdir / "session.v4.jsonl.zstd"
        if not f.exists():
            return
        try:
            from compression import zstd

            raw = zstd.decompress(f.read_bytes()).decode("utf-8", "replace")
        except Exception:
            return
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except ValueError:
                continue

    def iter_text(self, sid: str):
        """Unclipped searchable text from a DSH transcript.

        Yields the session title, every user/assistant text part, reasoning,
        tool calls (name + arguments) and tool results. Bookkeeping events
        (step/start, delivery-accepted, ...) are skipped: they carry no
        meaningful prose and would only add noise to search hits.
        """
        # The title is stored in the projection cache, not the transcript.
        cache, _ws = self._read_index()
        title = self._title_from(cache.get(sid) or {})
        if title:
            yield ("system", "title", title)

        for o in self._read_events(sid):
            kind = o.get("type")
            d = o.get("data") or {}
            if kind == "session/title":
                t = d.get("title")
                if t:
                    yield ("system", "title", str(t))
            elif kind == "user/message":
                for part in d.get("content") or []:
                    if not isinstance(part, dict):
                        continue
                    if part.get("type") == "text" and part.get("text"):
                        yield ("user", "text", str(part["text"]))
                    elif part.get("type") == "image":
                        att = part.get("attachment") or {}
                        yield (
                            "user",
                            "image",
                            f"[图片] {att.get('name') or 'image'}",
                        )
            elif kind == "assistant/message":
                m = d.get("message") or {}
                for part in m.get("content") or []:
                    if not isinstance(part, dict):
                        continue
                    ptype = part.get("type")
                    if ptype == "text" and part.get("text"):
                        yield ("assistant", "text", str(part["text"]))
                    elif ptype == "reasoning" and part.get("text"):
                        yield ("assistant", "reasoning", str(part["text"]))
            elif kind == "tool/call":
                name = str(d.get("name") or "")
                args = str(d.get("arguments") or "")
                if name or args:
                    yield ("assistant", "tool-call", f"{name} {args}".strip())
            elif kind == "tool/result":
                m = d.get("message") or {}
                parts = [
                    str(p.get("text") or "")
                    for p in (m.get("content") or [])
                    if isinstance(p, dict) and p.get("type") == "text"
                ]
                body = "\n".join(x for x in parts if x)
                if body:
                    yield ("tool", "tool-result", body)
            elif kind == "system/message":
                for part in d.get("content") or []:
                    if isinstance(part, dict) and part.get("text"):
                        yield ("system", "system", str(part["text"]))

    # --------------------------------------------------------------- preview

    def preview(self, sid: str) -> dict:
        """Render a DSH transcript read-only.

        The on-disk format is a zstd-compressed JSONL event stream. Only the
        events that carry human-readable content are surfaced; the rest
        (step/start, delivery-accepted, ...) are bookkeeping.
        """
        from core.model import (
            PREVIEW_MESSAGE_LIMIT,
            Message,
            clip,
        )

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

        if not is_safe_session_id(sid):
            out["reason"] = f"非法会话 ID：{sid!r}"
            return out

        sdir = self._find_session_dir(sid)
        pc = self.projcache_dir() / f"{sid}.json"
        cache, ws_map = self._read_index()
        rec = cache.get(sid) or {}

        out["title"] = self._title_from(rec) or ("(残留索引)" if sdir is None else "(无标题)")
        out["extra"] = {
            "cwd": self._identity_from(rec)[0],
            "workspaces": ws_map.get(sid, []),
            "has_content": sdir is not None,
            "metadata_path": str(pc) if pc.exists() else "",
            "attachments": len(list((self.attachments_dir()).glob("*/*")))
            if self.attachments_dir().exists()
            else 0,
        }

        if sdir is None:
            out["reason"] = (
                "该会话只剩元数据（幽灵条目），磁盘上已无对话正文，因此没有内容可预览。"
            )
            return out

        f = sdir / "session.v4.jsonl.zstd"
        if not f.exists():
            others = [x.name for x in list_files(sdir)]
            out["reason"] = (
                "会话目录中没有 session.v4.jsonl.zstd；"
                f"实际包含：{', '.join(others) if others else '（空目录）'}"
            )
            return out

        try:
            from compression import zstd

            raw = zstd.decompress(f.read_bytes()).decode("utf-8", "replace")
        except Exception as e:
            out["reason"] = f"无法解压会话正文（{type(e).__name__}: {e}）。"
            return out

        msgs: list[Message] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except ValueError:
                continue
            kind = o.get("type")
            t = o.get("time")
            d = o.get("data") or {}

            if kind == "user/message":
                for part in d.get("content") or []:
                    if not isinstance(part, dict):
                        continue
                    if part.get("type") == "text":
                        txt, cut = clip(str(part.get("text") or ""))
                        msgs.append(Message("user", txt, t, "text", truncated=cut))
                    elif part.get("type") == "image":
                        att = part.get("attachment") or {}
                        msgs.append(
                            Message(
                                "user",
                                f"[图片] {att.get('name') or 'image'} "
                                f"{att.get('width')}×{att.get('height')} "
                                f"{att.get('bytes', 0):,} 字节",
                                t,
                                "image",
                            )
                        )

            elif kind == "assistant/message":
                m = d.get("message") or {}
                for part in m.get("content") or []:
                    if not isinstance(part, dict):
                        continue
                    ptype = part.get("type")
                    if ptype == "text":
                        txt, cut = clip(str(part.get("text") or ""))
                        if txt.strip():
                            msgs.append(Message("assistant", txt, t, "text", truncated=cut))
                    elif ptype == "reasoning":
                        txt, cut = clip(str(part.get("text") or ""), 1200)
                        if txt.strip():
                            msgs.append(
                                Message("assistant", txt, t, "reasoning", truncated=cut)
                            )

            elif kind == "tool/call":
                args = str(d.get("arguments") or "")
                args, cut = clip(args, 700)
                msgs.append(
                    Message(
                        "assistant",
                        args,
                        t,
                        "tool-call",
                        tool=str(d.get("name") or ""),
                        truncated=cut,
                    )
                )

            elif kind == "tool/result":
                m = d.get("message") or {}
                texts = []
                for part in m.get("content") or []:
                    if isinstance(part, dict) and part.get("type") == "text":
                        texts.append(str(part.get("text") or ""))
                body, cut = clip("\n".join(texts), 1500)
                msgs.append(
                    Message(
                        "tool",
                        body,
                        t,
                        "tool-result",
                        is_error=bool(m.get("isError")),
                        truncated=cut,
                    )
                )

        out["total_messages"] = len(msgs)
        if len(msgs) > PREVIEW_MESSAGE_LIMIT:
            out["messages"] = [m.to_dict() for m in msgs[-PREVIEW_MESSAGE_LIMIT:]]
            out["truncated"] = True
        else:
            out["messages"] = [m.to_dict() for m in msgs]
        out["available"] = True
        if not msgs:
            out["reason"] = "会话正文为空（只有会话头，没有任何消息）。"
        return out

    # -------------------------------------------------------------- verify

    def verify_absent(self, sid: str) -> tuple[bool, str]:
        if self._find_session_dir(sid) is not None:
            return False, "会话正文目录仍然存在。"
        if (self.projcache_dir() / f"{sid}.json").exists():
            return False, "元数据缓存文件仍然存在（会留下幽灵条目）。"
        _cache, ws_map = self._read_index()
        if sid in ws_map:
            return False, f"workspace.json 中仍残留 {len(ws_map[sid])} 处引用。"
        return True, "正文、元数据、workspace.json 索引均已清除。"

    # --------------------------------------------------------------- health

    def health(self) -> list[dict]:
        findings: list[dict] = []
        cache, ws_map = self._read_index()

        ghosts = []
        for sid in cache:
            if self._find_session_dir(sid) is None:
                ghosts.append(sid)
        if ghosts:
            findings.append(
                {
                    "agent": self.id,
                    "level": "warn",
                    "kind": "ghost",
                    "title": f"{len(ghosts)} 个幽灵会话索引",
                    "detail": "有元数据但没有正文，会在侧边栏留下点不开的条目。",
                    "items": ghosts,
                    "size": sum(safe_size(self.projcache_dir() / f"{s}.json") for s in ghosts),
                    "action": "可在会话列表中勾选后删除。",
                }
            )

        orphans = [
            sid
            for sid in cache
            if sid.startswith("session-")
            and sid not in ws_map
            and self._find_session_dir(sid) is not None
        ]
        if orphans:
            findings.append(
                {
                    "agent": self.id,
                    "level": "info",
                    "kind": "orphan",
                    "title": f"{len(orphans)} 个会话不在任何工作区列表中",
                    "detail": "workspace.json 没有引用它们，DSH 中可能看不到。",
                    "items": orphans,
                    "size": 0,
                    "action": "",
                }
            )

        adir = self.attachments_dir()
        if adir.exists():
            try:
                others = self._all_content_text()
            except Exception:
                others = None
            if others is not None:
                dead = [
                    p
                    for p in adir.glob("*/*")
                    if p.is_file() and p.name.lower() not in others
                ]
                if dead:
                    findings.append(
                        {
                            "agent": self.id,
                            "level": "info",
                            "kind": "attachment",
                            "title": f"{len(dead)} 个无引用附件",
                            "detail": "内容寻址的附件，已不被任何会话引用。",
                            "items": [p.name for p in dead],
                            "size": sum(safe_size(p) for p in dead),
                            "action": "",
                        }
                    )

        # Legacy empty session directories (1 byte, no content file).
        empty = []
        for wsdir in list_dirs(self.sessions_dir()):
            for sdir in list_dirs(wsdir):
                if not any(sdir.iterdir()):
                    empty.append(str(sdir))
        if empty:
            findings.append(
                {
                    "agent": self.id,
                    "level": "info",
                    "kind": "empty_dir",
                    "title": f"{len(empty)} 个空会话目录",
                    "detail": "没有任何内容的会话目录，可安全删除。",
                    "items": empty,
                    "size": 0,
                    "action": "",
                }
            )
        return findings
