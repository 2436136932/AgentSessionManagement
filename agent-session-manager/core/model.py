"""Data model shared by adapters, planner, executor and the web API."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


# --------------------------------------------------------------------------
# Delete action kinds
# --------------------------------------------------------------------------

#: Remove a directory tree (moved to quarantine, so it stays reversible).
KIND_DIR = "remove_dir"
#: Remove a single file (moved to quarantine).
KIND_FILE = "remove_file"
#: Delete rows from a SQLite table, keyed by a column value.
KIND_SQLITE = "sqlite_delete"
#: Rewrite a JSON index to drop references to a session.
KIND_JSON_INDEX = "json_index_edit"
#: Drop unreferenced content-addressed attachment blobs (opt-in only).
KIND_ATTACHMENT = "attachment_gc"
#: Set a flag instead of deleting rows (agent-specific soft delete).
KIND_SOFT_DELETE = "sqlite_soft_delete"
#: Remove a registry key (a .reg export is taken first, for rollback).
KIND_REGISTRY = "registry_delete"
#: Remove a firewall rule (its full definition is exported first).
KIND_FIREWALL = "firewall_delete"
#: Remove a Start Menu / Desktop shortcut.
KIND_SHORTCUT = "shortcut_delete"
#: Actions that are only ever *reported*, never performed automatically:
#: removing a service or a scheduled task needs elevation and can break the
#: machine, so the user is told what to run instead.
KIND_MANUAL = "manual_action"


@dataclass
class Session:
    """One conversation as seen by one adapter."""

    agent: str                      # adapter id, e.g. "dsh"
    agent_label: str                # human label, e.g. "DeepSeek Harness"
    sid: str                        # stable session identifier
    title: str = ""
    cwd: str = ""
    created_at: int | None = None   # epoch ms
    updated_at: int | None = None   # epoch ms
    size: int = 0                   # bytes on disk attributable to this session
    file_count: int = 0
    # Paths that make up this session (for display / planning).
    paths: list[str] = field(default_factory=list)
    #: Session exists in an index but its content is gone.
    is_ghost: bool = False
    #: Content exists but no index entry references it.
    is_orphan: bool = False
    #: Whether this adapter can safely delete it.
    deletable: bool = True
    #: Why it is not deletable / what is special about it.
    note: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["created_iso"] = _iso(self.created_at)
        d["updated_iso"] = _iso(self.updated_at)
        d["size_h"] = _size(self.size)
        return d


@dataclass
class DeleteAction:
    """One concrete, auditable change the executor would make."""

    kind: str
    path: str                       # file/dir path, or "<db> → <table>" label for sqlite
    detail: str = ""
    size: int = 0
    reversible: bool = True
    # Populated for KIND_SQLITE: the database file, table, key column, key value.
    db_path: str = ""
    table: str = ""
    key_col: str = ""
    key_val: str = ""
    # Populated for KIND_JSON_INDEX.
    json_pointer: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["size_h"] = _size(self.size)
        return d


@dataclass
class DeletePlan:
    """The full, reviewable answer to 'what would deleting this do?'."""

    agent: str
    agent_label: str
    sid: str
    title: str = ""
    actions: list[DeleteAction] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    #: Set when deletion must not proceed (running agent, unknown format, ...).
    blocked: bool = False
    block_reason: str = ""
    #: Actions the user must opt into explicitly (e.g. attachment GC).
    optional_actions: list[DeleteAction] = field(default_factory=list)

    @property
    def total_size(self) -> int:
        return sum(a.size for a in self.actions)

    def to_dict(self) -> dict:
        return {
            "agent": self.agent,
            "agent_label": self.agent_label,
            "sid": self.sid,
            "title": self.title,
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "warnings": self.warnings,
            "total_size": self.total_size,
            "total_size_h": _size(self.total_size),
            "action_count": len(self.actions) + len(self.optional_actions),
            "actions": [a.to_dict() for a in self.actions],
            "optional_actions": [a.to_dict() for a in self.optional_actions],
        }


@dataclass
class Message:
    """One entry of a conversation, for the read-only preview.

    Deliberately shaped for reading, not for replay: only what a person needs
    to decide whether a session is worth keeping.
    """

    role: str                   # user | assistant | tool | system
    text: str = ""
    time: int | None = None     # epoch ms
    kind: str = "text"          # text | reasoning | tool-call | tool-result | image | note
    tool: str = ""              # tool name for tool-call / tool-result
    is_error: bool = False
    truncated: bool = False

    def to_dict(self) -> dict:
        return {
            "role": self.role,
            "text": self.text,
            "time": self.time,
            "time_iso": _iso(self.time),
            "kind": self.kind,
            "tool": self.tool,
            "is_error": self.is_error,
            "truncated": self.truncated,
        }


#: Per-message text cap for previews. Keeps a 4 MB transcript from becoming a
#: 4 MB HTTP response while still showing enough to judge the content.
PREVIEW_TEXT_LIMIT = 3000

#: Hard cap on messages returned in one preview.
PREVIEW_MESSAGE_LIMIT = 400


def clip(text: str, limit: int = PREVIEW_TEXT_LIMIT) -> tuple[str, bool]:
    """Trim text to `limit` characters, reporting whether it was cut."""
    if text is None:
        return "", False
    if len(text) <= limit:
        return text, False
    return text[:limit] + f"\n…（已截断，原长 {len(text):,} 字）", True


def _size(n) -> str:
    from .util import human_size  # local import to avoid cycles

    return human_size(n)


def _iso(ms) -> str:
    from .util import ms_to_iso

    return ms_to_iso(ms)
