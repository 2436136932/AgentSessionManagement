"""Adapter interface.

Every supported agent gets one adapter. An adapter must be able to answer,
safely and without guessing:

  * am I installed on this machine?            -> detect()
  * which directories do I own?                -> roots()
  * what sessions exist?                       -> list_sessions()
  * what exactly would deleting one change?     -> plan_delete()
  * is it really gone afterwards?              -> verify_absent()
  * anything worth cleaning up / warning about? -> health()

Design rules (learned from the survey of existing tools):
  * Never invent a path. If the on-disk format is not recognised, report the
    session as non-deletable instead of guessing.
  * A plan may only touch paths inside roots(). The executor re-checks this.
  * Report ghosts (index entry with no content) and orphans (content with no
    index entry) explicitly -- they are the residue that makes manual
    cleanup feel incomplete.
"""

from __future__ import annotations

from pathlib import Path

from core.model import DeletePlan, Session


class Adapter:
    #: stable machine id, e.g. "dsh"
    id: str = ""
    #: human label shown in the UI
    label: str = ""
    #: process names that indicate the agent is running (lowercase)
    processes: tuple[str, ...] = ()
    #: True when this adapter performs real deletion (others are browse-only)
    can_delete: bool = True
    #: Short description of where this agent stores data.
    storage_hint: str = ""

    # ---------------------------------------------------------------- basics

    def detect(self) -> bool:
        """True when the agent appears to be installed / has ever run here."""
        return bool(self.existing_roots())

    def roots(self) -> list[Path]:
        """Directories this adapter is allowed to modify. Override."""
        return []

    def existing_roots(self) -> list[Path]:
        return [p for p in self.roots() if Path(p).exists()]

    def footprint(self) -> tuple[int, int]:
        """(bytes, files) across all existing roots."""
        from core.util import dir_size

        total = 0
        count = 0
        for r in self.existing_roots():
            b, c = dir_size(r)
            total += b
            count += c
        return total, count

    def is_running(self) -> list[str]:
        """Names of running processes that belong to this agent."""
        from core.util import running_process_names

        live = running_process_names()
        return sorted(p for p in self.processes if p.lower() in live)

    # -------------------------------------------------------------- sessions

    def list_sessions(self) -> list[Session]:
        raise NotImplementedError

    # --------------------------------------------------------------- deletion

    def plan_delete(self, sid: str) -> DeletePlan:
        """Build a reviewable plan. Must not modify anything."""
        raise NotImplementedError

    def verify_absent(self, sid: str) -> tuple[bool, str]:
        """After deletion: (is_clean, human explanation).

        'Clean' means no session content and no dangling index entry remain.
        """
        raise NotImplementedError

    # ---------------------------------------------------------------- preview

    def preview(self, sid: str) -> dict:
        """Read-only rendering of one conversation.

        Returns:
            {
              "agent": str, "sid": str, "title": str,
              "available": bool,          # False when nothing is readable
              "reason": str,              # why, when unavailable
              "messages": [Message...],
              "truncated": bool,          # more messages existed than returned
              "total_messages": int,
              "extra": {...}              # adapter-specific facts
            }

        This is strictly read-only and must never raise: a preview that fails
        should explain itself so the UI can say why, rather than showing an
        error with no context.
        """
        from core.model import Message

        return {
            "agent": self.id,
            "sid": sid,
            "title": "",
            "available": False,
            "reason": "该 Agent 暂不支持会话内容预览。",
            "messages": [],
            "truncated": False,
            "total_messages": 0,
            "extra": {},
        }

    def iter_text(self, sid: str):
        """Yield (role, kind, text) for every searchable piece of this session.

        Separate from preview() on purpose: preview clips long messages and
        caps the number returned, so searching previews would miss matches in
        big sessions. This walks the raw store and yields *unclipped* text.

        Must be a generator, must never raise, and may yield nothing for an
        adapter whose content is not on this machine.
        """
        return iter(())

    # ----------------------------------------------------------------- extras

    def health(self) -> list[dict]:
        """Optional findings: orphans, ghosts, reclaimable caches."""
        return []

    # ----------------------------------------------------------------- helpers

    def _plan(self, sid: str, title: str = "") -> DeletePlan:
        return DeletePlan(agent=self.id, agent_label=self.label, sid=sid, title=title)
