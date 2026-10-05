"""CodeBuddy (Tencent) adapter.

IMPORTANT -- the on-disk layout is bigger than it looks, and getting it wrong
is destructive. Verified against a real installation:

    %LOCALAPPDATA%/CodeBuddyExtension/Data/
      <account>/VSCode/<workspace>/
        history/<projectId>/                     <- PROJECT, not a session
            index.json                           {"conversations":[{id,name,...}]}
            <conversationId>/                    <- ONE SESSION
                index.json                       the message list
                messages/                         message bodies
            .index_bak.json
        check-point/<projectId>/<conversationId>/
        file-tree/<projectId>/<conversationId>/
        plan-task/<projectId>/<conversationId>/

The trap: `history/<projectId>/` is a *project container* that holds an array of
conversations. Deleting it would destroy every conversation in that project at
once. The session is the *conversation id nested inside* it, and the same
conversation id appears in up to four sibling trees.

So a session is identified here as "<projectId>~<conversationId>", and a delete
touches only:

  * <tree>/<projectId>/<conversationId>/        for each tree that has it
  * the matching entry in <projectId>/index.json "conversations"

The project directory, its other conversations, and unrelated sub-directories
(checkpoint ids that are not conversation ids) are never touched.
"""

from __future__ import annotations

import json
from pathlib import Path

from adapters.base import Adapter
from core.model import KIND_DIR, KIND_JSON_INDEX, DeleteAction, DeletePlan, Session
from core.util import (
    dir_size,
    home,
    is_safe_session_id,
    list_dirs,
    local_appdata,
    read_json,
    safe_size,
)

#: Sibling trees that can hold per-conversation data.
_TREES = ("history", "check-point", "file-tree", "plan-task")

#: Separator in the composite session id "<projectId>~<conversationId>".
SEP = "~"


class CodeBuddyAdapter(Adapter):
    id = "codebuddy"
    label = "CodeBuddy"
    processes = ("codebuddy.exe",)
    can_delete = True
    storage_hint = "~/.codebuddy + %LOCALAPPDATA%/CodeBuddyExtension"

    def base(self) -> Path:
        return home() / ".codebuddy"

    def history_json(self) -> Path:
        return self.base() / "expert-history.json"

    def ext_data(self) -> Path:
        return local_appdata() / "CodeBuddyExtension" / "Data"

    def roots(self) -> list[Path]:
        return [self.base(), local_appdata() / "CodeBuddyExtension" / "Data"]

    def detect(self) -> bool:
        return self.base().exists() or self.ext_data().exists()

    # --------------------------------------------------------------- workspace

    def _workspaces(self) -> list[Path]:
        """Every <account>/VSCode/<workspace> directory."""
        out: list[Path] = []
        for acct in list_dirs(self.ext_data()):
            vscode = acct / "VSCode"
            for ws in list_dirs(vscode):
                out.append(ws)
        return out

    def _projects(self) -> list[tuple[Path, str]]:
        """(workspace_dir, projectId) for every project with a history index."""
        out: list[tuple[Path, str]] = []
        for ws in self._workspaces():
            hist = ws / "history"
            for proj in list_dirs(hist):
                if (proj / "index.json").exists() or any(
                    (ws / t / proj.name).is_dir() for t in _TREES
                ):
                    out.append((ws, proj.name))
        return out

    @staticmethod
    def _split_sid(sid: str) -> tuple[str, str] | None:
        if SEP not in sid:
            return None
        project, conv = sid.split(SEP, 1)
        if not is_safe_session_id(project) or not is_safe_session_id(conv):
            return None
        return project, conv

    @staticmethod
    def _project_index(ws: Path, project: str) -> Path:
        return ws / "history" / project / "index.json"

    def _read_project_index(self, ws: Path, project: str) -> list[dict]:
        obj = read_json(self._project_index(ws, project), None)
        if isinstance(obj, dict) and isinstance(obj.get("conversations"), list):
            return [c for c in obj["conversations"] if isinstance(c, dict)]
        return []

    # ------------------------------------------------------------------- scan

    def list_sessions(self) -> list[Session]:
        out: list[Session] = []
        seen: set[str] = set()

        for ws, project in self._projects():
            for conv in self._read_project_index(ws, project):
                cid = str(conv.get("id") or "")
                if not is_safe_session_id(cid):
                    continue
                sid = f"{project}{SEP}{cid}"
                seen.add(sid)

                dirs = self._session_dirs(ws, project, cid)
                size = 0
                files = 0
                for d in dirs:
                    b, c = dir_size(d)
                    size += b
                    files += c
                idx = self._project_index(ws, project)
                size += safe_size(idx)
                files += 1 if idx.exists() else 0

                out.append(
                    Session(
                        agent=self.id,
                        agent_label=self.label,
                        sid=sid,
                        title=str(conv.get("name") or "").strip() or "(无标题)",
                        cwd=self._workspace_label(ws),
                        created_at=_iso_to_ms(conv.get("createdAt")),
                        updated_at=_iso_to_ms(
                            conv.get("lastMessageAt") or conv.get("createdAt")
                        ),
                        size=size,
                        file_count=files,
                        paths=[str(d) for d in dirs] + [str(idx)],
                        note=f"项目 {project[:12]}…",
                        extra={
                            "project": project,
                            "conversation": cid,
                            "type": conv.get("type"),
                            "trees": [d.parent.name for d in dirs],
                        },
                    )
                )

        # Conversation directories with no index entry (index lost / partial).
        for ws, project in self._projects():
            hist = ws / "history" / project
            if not hist.is_dir():
                continue
            for d in list_dirs(hist):
                if d.name.startswith("."):
                    continue
                sid = f"{project}{SEP}{d.name}"
                if sid in seen:
                    continue
                seen.add(sid)
                dirs = self._session_dirs(ws, project, d.name)
                size = 0
                files = 0
                for x in dirs:
                    b, c = dir_size(x)
                    size += b
                    files += c
                out.append(
                    Session(
                        agent=self.id,
                        agent_label=self.label,
                        sid=sid,
                        title="(索引中缺失的会话)",
                        size=size,
                        file_count=files,
                        updated_at=self._mtime(d),
                        paths=[str(x) for x in dirs],
                        is_orphan=True,
                        note="项目索引里没有这条会话记录。",
                        extra={"project": project, "conversation": d.name},
                    )
                )

        out.sort(key=lambda s: -(s.updated_at or 0))
        return out

    @staticmethod
    def _mtime(p: Path) -> int | None:
        try:
            return int(p.stat().st_mtime * 1000)
        except OSError:
            return None

    @staticmethod
    def _workspace_label(ws: Path) -> str:
        """Workspace folder names are base64 of the project path.

        e.g. "ZTovd29ya2J1ZGR5YXBpLW1haW4=" -> "Z:/workbuddyapi-main".
        Falls back to the raw name when it is not decodable.
        """
        import base64
        import binascii

        name = ws.name
        if not name:
            return ""
        try:
            padded = name + "=" * (-len(name) % 4)
            decoded = base64.b64decode(padded, validate=False).decode("utf-8")
            if decoded and all(ch.isprintable() for ch in decoded):
                return decoded
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass
        return name

    def _session_dirs(self, ws: Path, project: str, conv: str) -> list[Path]:
        """Directories belonging to exactly this conversation."""
        found: list[Path] = []
        for tree in _TREES:
            cand = ws / tree / project / conv
            if cand.is_dir():
                found.append(cand)
        return found

    # --------------------------------------------------------------- deletion

    def plan_delete(self, sid: str) -> DeletePlan:
        plan = self._plan(sid)
        parts = self._split_sid(sid)
        if parts is None:
            plan.blocked = True
            plan.block_reason = (
                f"无法解析会话 ID：{sid!r}（应为 <项目ID>~<会话ID>）"
            )
            return plan
        project, conv = parts

        # Locate the workspace that actually owns this conversation.
        targets: list[Path] = []
        owner_ws: Path | None = None
        for ws, proj in self._projects():
            if proj != project:
                continue
            dirs = self._session_dirs(ws, project, conv)
            if dirs or conv in {str(c.get("id")) for c in self._read_project_index(ws, project)}:
                owner_ws = ws
                targets = dirs
                break

        if owner_ws is None:
            plan.blocked = True
            plan.block_reason = "在 CodeBuddy 的数据目录中找不到该会话。"
            return plan

        plan.title = next(
            (
                str(c.get("name") or "").strip()
                for c in self._read_project_index(owner_ws, project)
                if str(c.get("id")) == conv
            ),
            "",
        ) or "(无标题)"

        for d in targets:
            size, files = dir_size(d)
            # Path shape: <workspace>/<tree>/<project>/<conversation>, so the
            # tree name is two levels up (d.parent is the project id).
            tree = d.parent.parent.name
            plan.actions.append(
                DeleteAction(
                    kind=KIND_DIR,
                    path=str(d),
                    detail=f"{tree} 中该会话的数据目录（{files} 个文件）",
                    size=size,
                    reversible=True,
                )
            )

        idx = self._project_index(owner_ws, project)
        in_index = any(
            str(c.get("id")) == conv
            for c in self._read_project_index(owner_ws, project)
        )
        if in_index:
            plan.actions.append(
                DeleteAction(
                    kind=KIND_JSON_INDEX,
                    path=str(idx),
                    detail="从项目 index.json 的 conversations 列表移除该会话",
                    size=safe_size(idx),
                    reversible=True,
                    json_pointer=str(idx),
                    key_val=conv,
                    key_col="drop_conversation_entry",
                )
            )

        if not plan.actions:
            plan.blocked = True
            plan.block_reason = "没有找到属于该会话的任何数据。"
            return plan

        # Explicitly reassure about what is NOT touched.
        plan.warnings.append(
            f"仅删除该会话；同项目中的其他会话与项目目录本身（{project[:12]}…）不会被改动。"
        )
        plan.warnings.append(
            "CodeBuddy 的对话正文可能保存在云端，本地删除仅清理本地索引与缓存。"
        )

        if self.is_running():
            plan.blocked = True
            plan.block_reason = "CodeBuddy 正在运行，请先退出后再删除。"
        return plan

    def iter_text(self, sid: str):
        """Unclipped searchable text from a CodeBuddy conversation."""
        parts = self._split_sid(sid)
        if parts is None:
            return
        project, conv = parts

        owner_ws = None
        conv_dir = None
        for ws, proj in self._projects():
            if proj != project:
                continue
            cand = ws / "history" / project / conv
            if cand.is_dir():
                owner_ws, conv_dir = ws, cand
                break
        if conv_dir is None:
            return

        for c in self._read_project_index(owner_ws, project):
            if str(c.get("id")) == conv and c.get("name"):
                yield ("system", "title", str(c["name"]))

        idx_obj = read_json(conv_dir / "index.json", {}) or {}
        entries = idx_obj.get("messages") if isinstance(idx_obj, dict) else None
        if not isinstance(entries, list):
            return
        mdir = conv_dir / "messages"
        files = {p.stem: p for p in mdir.rglob("*.json")} if mdir.is_dir() else {}

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            role = str(entry.get("role") or "assistant")
            f = files.get(str(entry.get("id") or ""))
            if f is None or not f.exists():
                continue
            try:
                body = json.loads(f.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                continue
            inner = body.get("message")
            if isinstance(inner, str):
                try:
                    inner = json.loads(inner)
                except ValueError:
                    yield (role, "text", inner)
                    continue
            if not isinstance(inner, dict):
                continue
            for part in inner.get("content") or []:
                if not isinstance(part, dict):
                    continue
                ptype = part.get("type")
                if ptype == "text" and part.get("text"):
                    yield (role, "text", str(part["text"]))
                elif ptype == "reasoning" and part.get("text"):
                    yield ("assistant", "reasoning", str(part["text"]))
                elif ptype in ("tool-call", "tool_call"):
                    name = str(part.get("toolName") or part.get("name") or "")
                    args = str(part.get("args") or part.get("arguments") or "")
                    if name or args:
                        yield ("assistant", "tool-call", f"{name} {args}".strip())
                elif ptype in ("tool-result", "tool_result"):
                    res = part.get("result")
                    txt = (
                        res
                        if isinstance(res, str)
                        else json.dumps(res, ensure_ascii=False, default=str)
                    )
                    if txt:
                        yield ("tool", "tool-result", txt)

    # --------------------------------------------------------------- preview

    def preview(self, sid: str) -> dict:
        """Render a CodeBuddy conversation read-only.

        Layout: <project>/index.json lists messages as
        {"id","role","type",...}; the actual body of each message lives in
        <conversation>/messages/<id>.json as {"role","message",...} where
        "message" is itself a JSON *string* holding {"role","content":[...]}.
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

        parts = self._split_sid(sid)
        if parts is None:
            out["reason"] = (
                f"无法解析会话 ID：{sid!r}（应为 <项目ID>~<会话ID>）"
            )
            return out
        project, conv = parts

        # Locate the conversation directory.
        conv_dir: Path | None = None
        owner_ws: Path | None = None
        for ws, proj in self._projects():
            if proj != project:
                continue
            cand = ws / "history" / project / conv
            if cand.is_dir():
                conv_dir = cand
                owner_ws = ws
                break

        index = []
        if owner_ws is not None:
            index = self._read_project_index(owner_ws, project)

        out["title"] = next(
            (
                str(c.get("name") or "").strip()
                for c in index
                if str(c.get("id")) == conv
            ),
            "",
        ) or "(无标题)"
        out["extra"] = {
            "project": project,
            "workspace": str(owner_ws) if owner_ws else "",
            "in_index": any(str(c.get("id")) == conv for c in index),
            # Path shape is <workspace>/<tree>/<project>/<conversation>.
            "trees": [
                d.parent.parent.name
                for d in self._session_dirs(owner_ws, project, conv)
            ]
            if owner_ws
            else [],
        }

        if conv_dir is None:
            out["reason"] = (
                "该项目索引里有这条会话，但磁盘上已无对应数据目录，没有内容可预览。"
            )
            return out

        idx_file = conv_dir / "index.json"
        mdir = conv_dir / "messages"
        try:
            idx_obj = read_json(idx_file, {}) or {}
        except Exception:
            idx_obj = {}
        entries = idx_obj.get("messages") if isinstance(idx_obj, dict) else None
        if not isinstance(entries, list):
            entries = []

        files = {p.stem: p for p in mdir.rglob("*.json")} if mdir.is_dir() else {}

        msgs: list[Message] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            mid = str(entry.get("id") or "")
            role = str(entry.get("role") or "assistant")
            f = files.get(mid)
            text = ""
            tool = ""
            kind = "text"
            is_err = False
            ts = _iso_to_ms(entry.get("createdAt"))

            if f is not None and f.exists():
                try:
                    body = json.loads(f.read_text(encoding="utf-8", errors="replace"))
                except (OSError, ValueError):
                    body = {}
                inner = body.get("message")
                if isinstance(inner, str):
                    try:
                        inner = json.loads(inner)
                    except ValueError:
                        inner = None
                ts = ts or _iso_to_ms(body.get("createdAt"))
                if isinstance(inner, dict):
                    chunks: list[str] = []
                    for part in inner.get("content") or []:
                        if not isinstance(part, dict):
                            continue
                        ptype = part.get("type")
                        if ptype == "text":
                            chunks.append(str(part.get("text") or ""))
                        elif ptype == "reasoning":
                            r, _c = clip(str(part.get("text") or ""), 1000)
                            if r.strip():
                                chunks.append(f"[思考] {r}")
                        elif ptype in ("tool-call", "tool_call"):
                            tool = str(part.get("toolName") or part.get("name") or "")
                            a, _c = clip(str(part.get("args") or part.get("arguments") or ""), 500)
                            chunks.append(f"[调用 {tool}] {a}")
                            kind = "tool-call"
                        elif ptype in ("tool-result", "tool_result"):
                            tool = str(part.get("toolName") or "")
                            res = part.get("result")
                            r, _c = clip(
                                res if isinstance(res, str) else json.dumps(res, ensure_ascii=False),
                                800,
                            )
                            chunks.append(f"[结果 {tool}] {r}")
                            kind = "tool-result"
                            is_err = "error" in r.lower()[:200]
                    text = "\n".join(chunks)
                elif isinstance(inner, str):
                    text = inner
            if not text:
                text = f"（消息正文文件缺失：{mid}.json）" if f is None else "（空消息）"

            body_text, cut = clip(text)
            msgs.append(
                Message(
                    role,
                    body_text,
                    ts,
                    kind,
                    tool=tool,
                    is_error=is_err,
                    truncated=cut,
                )
            )

            if len(msgs) >= PREVIEW_MESSAGE_LIMIT * 2:
                break

        out["total_messages"] = len(entries) if entries else len(msgs)
        if len(msgs) > PREVIEW_MESSAGE_LIMIT:
            out["messages"] = [m.to_dict() for m in msgs[:PREVIEW_MESSAGE_LIMIT]]
            out["truncated"] = True
        else:
            out["messages"] = [m.to_dict() for m in msgs]
        out["available"] = True
        if not msgs:
            out["reason"] = "该会话目录下没有可读的消息文件。"
        return out

    # --------------------------------------------------------------- verify

    def verify_absent(self, sid: str) -> tuple[bool, str]:
        parts = self._split_sid(sid)
        if parts is None:
            return False, f"无法解析会话 ID：{sid!r}"
        project, conv = parts

        left: list[str] = []
        for ws, proj in self._projects():
            if proj != project:
                continue
            for d in self._session_dirs(ws, project, conv):
                if d.exists():
                    left.append(str(d))
            if any(
                str(c.get("id")) == conv
                for c in self._read_project_index(ws, project)
            ):
                left.append(str(self._project_index(ws, project)))
        if left:
            return False, "仍然存在：" + "；".join(left)

        # The project container must still be there -- that is the point.
        still_there = any(
            proj == project for _ws, proj in self._projects()
        )
        if not still_there:
            return False, "项目目录被误删，这不是预期结果。"
        return True, "会话数据与索引条目均已清除（项目目录保留）。"

    # --------------------------------------------------------------- health

    def health(self) -> list[dict]:
        findings: list[dict] = []

        # Conversations present in the index but with no data anywhere.
        index_only: list[str] = []
        for ws, project in self._projects():
            for conv in self._read_project_index(ws, project):
                cid = str(conv.get("id") or "")
                if not is_safe_session_id(cid):
                    continue
                if not self._session_dirs(ws, project, cid):
                    index_only.append(f"{project[:10]}…~{cid}")
        if index_only:
            findings.append(
                {
                    "agent": self.id,
                    "level": "info",
                    "kind": "index_only",
                    "title": f"{len(index_only)} 个仅在索引中的会话",
                    "detail": "项目 index.json 有记录，但本地已无对应数据目录。",
                    "items": index_only,
                    "size": 0,
                    "action": "",
                }
            )

        # Conversation directories missing from the project index (orphans).
        orphan_dirs: list[str] = []
        for ws, project in self._projects():
            known = {str(c.get("id")) for c in self._read_project_index(ws, project)}
            hist = ws / "history" / project
            if not hist.is_dir():
                continue
            for d in list_dirs(hist):
                if d.name.startswith(".") or d.name in known:
                    continue
                orphan_dirs.append(f"{project[:10]}…~{d.name}")
        if orphan_dirs:
            findings.append(
                {
                    "agent": self.id,
                    "level": "warn",
                    "kind": "orphan",
                    "title": f"{len(orphan_dirs)} 个会话未登记在项目索引中",
                    "detail": "有数据目录但项目 index.json 里没有它，CodeBuddy 界面中可能看不到。",
                    "items": orphan_dirs,
                    "size": 0,
                    "action": "可在会话列表中删除。",
                }
            )

        # Zero-byte checkpoint/history leftovers.
        empty: list[str] = []
        for ws in self._workspaces():
            for tree in ("check-point", "history"):
                base = ws / tree
                for proj in list_dirs(base):
                    for child in list_dirs(proj):
                        total, _c = dir_size(child)
                        if total == 0:
                            empty.append(str(child))
        if empty:
            findings.append(
                {
                    "agent": self.id,
                    "level": "info",
                    "kind": "empty_dir",
                    "title": f"{len(empty)} 个空数据目录",
                    "detail": "目录中没有任何数据。",
                    "items": empty,
                    "size": 0,
                    "action": "",
                }
            )
        return findings

    # --------------------------------------------------------------- index edit

    def drop_index_key(self, sid: str) -> None:
        """Remove the conversation entry from its project's index.json."""
        from core.util import write_json_atomic

        parts = self._split_sid(sid)
        if parts is None:
            return
        project, conv = parts
        for ws, proj in self._projects():
            if proj != project:
                continue
            p = self._project_index(ws, project)
            obj = read_json(p, None)
            if isinstance(obj, dict) and isinstance(obj.get("conversations"), list):
                before = len(obj["conversations"])
                obj["conversations"] = [
                    c
                    for c in obj["conversations"]
                    if not (isinstance(c, dict) and str(c.get("id")) == conv)
                ]
                if len(obj["conversations"]) != before:
                    write_json_atomic(p, obj)


def _iso_to_ms(v) -> int | None:
    """CodeBuddy stores ISO-8601 strings with milliseconds and a Z suffix."""
    if not isinstance(v, str) or not v.strip():
        return None
    s = v.strip().replace("Z", "+00:00")
    try:
        from datetime import datetime

        return int(datetime.fromisoformat(s).timestamp() * 1000)
    except ValueError:
        return None
