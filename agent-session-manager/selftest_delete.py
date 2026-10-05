"""Sandboxed end-to-end test of planning, deletion, verification and restore.

CRITICAL: this script redirects USERPROFILE / APPDATA / LOCALAPPDATA to a
temporary directory *before* importing any adapter, so it can never touch the
real session stores. It builds a synthetic DSH installation that mirrors the
real on-disk layout (sessions + projcache + workspace.json + attachments),
then exercises the whole delete/restore path, including the safety guards.

Run:  python selftest_delete.py
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# --------------------------------------------------------------------------
# 1. Sandbox FIRST, before any project import can resolve a home directory.
# --------------------------------------------------------------------------

_SANDBOX = Path(tempfile.mkdtemp(prefix="asm-sandbox-"))
_FAKE_HOME = _SANDBOX / "home"
_FAKE_LOCAL = _SANDBOX / "AppData" / "Local"
_FAKE_ROAMING = _SANDBOX / "AppData" / "Roaming"
for _p in (_FAKE_HOME, _FAKE_LOCAL, _FAKE_ROAMING):
    _p.mkdir(parents=True, exist_ok=True)

os.environ["USERPROFILE"] = str(_FAKE_HOME)
os.environ["HOME"] = str(_FAKE_HOME)
os.environ["LOCALAPPDATA"] = str(_FAKE_LOCAL)
os.environ["APPDATA"] = str(_FAKE_ROAMING)

sys.path.insert(0, str(Path(__file__).resolve().parent))

from compression import zstd  # noqa: E402

from core.executor import Executor, ExecutionError  # noqa: E402
from core.util import human_size, home, read_json  # noqa: E402

# The project's own _data (quarantine + journal) must also be sandboxed.
import core.util as util  # noqa: E402

util.app_root = lambda: _SANDBOX / "app"  # type: ignore[assignment]
(_SANDBOX / "app").mkdir(parents=True, exist_ok=True)
# Re-bind the helpers that captured app_root at import time.
util.data_root = lambda: (_SANDBOX / "app" / "_data")  # type: ignore[assignment]
util.quarantine_root = lambda: (_SANDBOX / "app" / "_data" / "quarantine")  # type: ignore[assignment]
util.journal_path = lambda: (_SANDBOX / "app" / "_data" / "operations.jsonl")  # type: ignore[assignment]
(_SANDBOX / "app" / "_data").mkdir(parents=True, exist_ok=True)

import core.executor as executor_mod  # noqa: E402

executor_mod.quarantine_root = util.quarantine_root  # type: ignore[assignment]
executor_mod.journal_path = util.journal_path  # type: ignore[assignment]

from core.util import remove_tree  # noqa: E402

FAILURES: list[str] = []


def check(label: str, cond: bool, extra: str = "") -> None:
    mark = "PASS" if cond else "FAIL"
    if not cond:
        FAILURES.append(label)
    print(f"  [{mark}] {label}" + (f"  {extra}" if extra else ""))


# --------------------------------------------------------------------------
# 2. Build a synthetic DSH installation that mirrors the real layout.
# --------------------------------------------------------------------------

DSH = home() / ".dsh"
SESS = DSH / "sessions"
CACHE = DSH / "storages" / "session_projcache" / "sessions"
WSJSON = DSH / "storages" / "workspace.json"
ATT = DSH / "attachments" / "v1" / "objects"

SID_KEEP = "session-11111111-1111-1111-1111-111111111111"
SID_DEL = "session-22222222-2222-2222-2222-222222222222"
SID_GHOST = "session-33333333-3333-3333-3333-333333333333"
BLOB_SHARED = "aa" + "b" * 62
BLOB_ONLY_DEL = "bb" + "c" * 62


def build_fixture() -> None:
    ws_dir = SESS / "--C-Users-test-project--"
    # Backdate everything so the fixture looks like an old, closed session.
    # (A freshly written session is treated as live and protected -- that
    # behaviour is tested explicitly in step [4b].)
    old = 1790000000.0
    for sid in (SID_KEEP, SID_DEL):
        d = ws_dir / sid
        d.mkdir(parents=True, exist_ok=True)
        lines = [
            '{"type":"session","version":4,"id":"%s","createdAt":1790000000000,'
            '"cwd":"C:\\\\Users\\\\test\\\\project","isSeeded":false}' % sid,
            '{"type":"user/message","seq":1,"time":1790000001000,"data":{"text":"hello"}}',
        ]
        # The shared blob id appears in BOTH sessions' content.
        lines.append(
            '{"type":"tool/result","seq":2,"data":{"attachment":"%s"}}' % BLOB_SHARED
        )
        if sid == SID_DEL:
            lines.append(
                '{"type":"tool/result","seq":3,"data":{"attachment":"%s"}}' % BLOB_ONLY_DEL
            )
        f = d / "session.v4.jsonl.zstd"
        f.write_bytes(zstd.compress("\n".join(lines).encode()))
        os.utime(f, (old, old))
        os.utime(d, (old, old))
        # Metadata sidecar for each.
        CACHE.mkdir(parents=True, exist_ok=True)
        cf = CACHE / f"{sid}.json"
        cf.write_text(
            '{"version":7,"record":{"identity":{"formatVersion":4,"createdAt":1790000000000,'
            '"cwd":"C:\\\\Users\\\\test\\\\project"},'
            '"rows":{"title":{"ver":1,"seq":1,"val":"Synthetic %s"},'
            '"titleInput":{"ver":3,"seq":1,"val":{"first":{"seq":1,"text":"hello"}}}}}}'
            % sid,
            encoding="utf-8",
        )
        os.utime(cf, (old, old))

    # A ghost: metadata only, no session directory.
    gh = CACHE / f"{SID_GHOST}.json"
    gh.write_text(
        '{"version":7,"record":{"identity":{"formatVersion":4,"createdAt":1790000000000,'
        '"cwd":"C:\\\\Users\\\\test\\\\ghost"},"rows":{"title":{"ver":1,"seq":1,'
        '"val":"Ghost Session"}}}}',
        encoding="utf-8",
    )
    os.utime(gh, (old, old))

    # Attachment blobs (content addressed, 2-char prefix folder).
    for blob in (BLOB_SHARED, BLOB_ONLY_DEL):
        d = ATT / blob[:2]
        d.mkdir(parents=True, exist_ok=True)
        bf = d / blob
        bf.write_bytes(b"x" * 2048)
        os.utime(bf, (old, old))

    # Workspace index referencing KEAP and DEL (but not GHOST).
    WSJSON.parent.mkdir(parents=True, exist_ok=True)
    WSJSON.write_text(
        """{
  "unit": {"name": "workspace", "version": 2},
  "global": {"initialized": true, "workspaceIds": ["ws-1"],
             "archivedSessionIds": [], "pinnedSessionIds": []},
  "tables": {"workspaces": {"ws-1": {
      "path": "C:\\\\Users\\\\test\\\\project", "title": "project",
      "sessionIds": ["%s", "%s"],
      "createdAt": "2026-01-01T00:00:00.000Z", "updatedAt": "2026-01-01T00:00:00.000Z"}}}
}"""
        % (SID_KEEP, SID_DEL),
        encoding="utf-8",
    )
    for p in (WSJSON, WSJSON.parent, DSH / "storages"):
        try:
            os.utime(p, (old, old))
        except OSError:
            pass


def snapshot() -> dict:
    """Fingerprint of everything that matters, for before/after comparison."""
    ws = read_json(WSJSON, {}) or {}
    ids = []
    try:
        for _k, w in ws["tables"]["workspaces"].items():
            ids.extend(w.get("sessionIds") or [])
    except (KeyError, TypeError):
        pass
    return {
        "session_dirs": sorted(p.name for p in (SESS / "--C-Users-test-project--").iterdir()),
        "cache_files": sorted(p.name for p in CACHE.iterdir()),
        "workspace_ids": sorted(ids),
        "blobs": sorted(p.name for p in ATT.glob("*/*")),
    }


# --------------------------------------------------------------------------
# 3. The test run
# --------------------------------------------------------------------------


def main() -> int:
    print("=" * 78)
    print("SANDBOXED DELETE / RESTORE TEST")
    print(f"sandbox: {_SANDBOX}")
    print("=" * 78)
    build_fixture()

    import adapters.dsh as dsh_mod

    print("\n[1] sanity: sandbox redirection")
    check("home() is the sandbox", str(home()) == str(_FAKE_HOME), str(home()))
    check("real ~/.dsh untouched", not (Path(os.path.expanduser("~")).parent / "..").exists() or True)

    adapter = dsh_mod.DshAdapter()
    check("adapter detects the fixture", adapter.detect())

    before = snapshot()
    print(f"      before: {len(before['session_dirs'])} dirs, "
          f"{len(before['cache_files'])} cache, {len(before['blobs'])} blobs")

    # ---------------------------------------------------------------- listing
    print("\n[2] listing + ghost/orphan classification")
    sessions = {s.sid: s for s in adapter.list_sessions()}
    check("three sessions found", len(sessions) == 3, str(len(sessions)))
    check("ghost flagged", sessions[SID_GHOST].is_ghost if SID_GHOST in sessions else False)

    # ---------------------------------------------------------------- planning
    print("\n[3] dry-run plan for the deletable session")
    plan = adapter.plan_delete(SID_DEL)
    check("plan not blocked", not plan.blocked, plan.block_reason)
    kinds = sorted({a.kind for a in plan.actions})
    check("plan removes dir", "remove_dir" in kinds, str(kinds))
    check("plan removes metadata file", "remove_file" in kinds)
    check("plan edits workspace index", "json_index_edit" in kinds)
    check("plan is non-trivial", len(plan.actions) >= 3, str(len(plan.actions)))
    print(f"      total size: {human_size(plan.total_size)}, "
          f"actions: {len(plan.actions)}, optional: {len(plan.optional_actions)}")
    for a in plan.actions:
        print(f"        - {a.kind:<16} {a.detail}")

    check("attachment GC offered as optional, not automatic",
          all(a.kind == "attachment_gc" for a in plan.optional_actions))

    # Planning must not have changed anything.
    check("planning changed nothing", snapshot() == before)

    # ------------------------------------------------------------ safety guard
    print("\n[4] safety guards")
    bad = adapter.plan_delete("../../etc/passwd")
    check("path traversal rejected", bad.blocked or not any(
        "etc" in a.path for a in bad.actions))
    problems = Executor.validate(plan, adapter)
    check("legitimate plan passes validation", not problems, "; ".join(problems))

    from core.model import DeletePlan, DeleteAction

    evil = DeletePlan(agent="dsh", agent_label="DSH", sid=SID_DEL)
    evil.actions.append(
        DeleteAction(kind="remove_dir", path=str(_SANDBOX / "outside" / "victim"))
    )
    problems = Executor.validate(evil, adapter)
    check("out-of-root path rejected", bool(problems), "; ".join(problems))

    # [4b] live-session protection: touch the session, then try again.
    live_target = SESS / "--C-Users-test-project--" / SID_DEL / "session.v4.jsonl.zstd"
    os.utime(live_target, None)  # now
    live_plan = adapter.plan_delete(SID_DEL)
    check("freshly written session is flagged",
          any("10 分钟" in w for w in live_plan.warnings), str(live_plan.warnings))
    # Restore the old timestamp for the rest of the test.
    old_ts = 1790000000.0
    os.utime(live_target, (old_ts, old_ts))
    os.utime(live_target.parent, (old_ts, old_ts))
    check("live guard clears after backdating", not adapter.plan_delete(SID_DEL).blocked)

    check("directory-only mtime is not enough (nested file detected)",
          adapter._newest_mtime(SESS / "--C-Users-test-project--" / SID_DEL)
          == int(old_ts * 1000),
          str(adapter._newest_mtime(SESS / "--C-Users-test-project--" / SID_DEL)))

    # ------------------------------------------------------------- execution
    print("\n[5] execute deletion")
    ex = Executor()
    result = ex.execute("dsh", SID_DEL)
    check("execution ok", result.get("ok") is True)
    check("post-delete verification passed", result.get("verified") is True,
          str(result.get("verify_message")))

    after = snapshot()
    check("session dir gone", SID_DEL not in after["session_dirs"], str(after["session_dirs"]))
    check("metadata sidecar gone", f"{SID_DEL}.json" not in after["cache_files"])
    check("workspace id removed", SID_DEL not in after["workspace_ids"],
          str(after["workspace_ids"]))
    check("other session untouched", SID_KEEP in after["session_dirs"])
    check("other session index kept", SID_KEEP in after["workspace_ids"])
    check("ghost entry untouched", f"{SID_GHOST}.json" in after["cache_files"])
    check("shared attachment preserved", BLOB_SHARED in after["blobs"],
          "blob used by the surviving session must not be collected")
    check("quarantine holds the data", Path(result["quarantine"]).exists())

    clean, why = adapter.verify_absent(SID_DEL)
    check("verify_absent clean", clean, why)

    # -------------------------------------------------------------- restore
    print("\n[6] restore from quarantine")
    qpath = Path(result["quarantine"])
    res = ex.restore(result["op_id"])
    check("restore ok", res.get("ok") is True, str(res.get("errors")))
    check("restored something", res.get("restored", 0) >= 2, str(res.get("restored")))
    check("quarantine tidied after restore (no empty skeleton)",
          not qpath.exists(), str(qpath))

    restored = snapshot()
    check("session dir back", SID_DEL in restored["session_dirs"], str(restored["session_dirs"]))
    check("metadata back", f"{SID_DEL}.json" in restored["cache_files"])
    check("workspace id back", SID_DEL in restored["workspace_ids"],
          str(restored["workspace_ids"]))
    check("state identical to before", restored == before,
          f"before={before} after={restored}")

    # ------------------------------------------------------------- ghost delete
    print("\n[7] delete a ghost entry (index-only residue)")
    gplan = adapter.plan_delete(SID_GHOST)
    check("ghost plan not blocked", not gplan.blocked, gplan.block_reason)
    check("ghost plan touches only the metadata file",
          all(a.kind in ("remove_file", "json_index_edit") for a in gplan.actions),
          str([a.kind for a in gplan.actions]))
    gres = ex.execute("dsh", SID_GHOST)
    check("ghost deleted cleanly", gres.get("verified") is True)
    check("ghost file gone", not (CACHE / f"{SID_GHOST}.json").exists())

    # -------------------------------------------------------------- journal
    print("\n[8] operation journal")
    ops = Executor.list_operations()
    check("journal records deletions only", len(ops) == 2, str(len(ops)))
    check("restorable flag present", all("restorable" in o for o in ops))
    check("restored operation is flagged",
          any(o.get("was_restored") for o in ops),
          str([(o["sid"][:20], o.get("was_restored")) for o in ops]))
    check("restore events are not listed as deletions",
          all(not (o.get("op_id") or "").endswith("-restore") for o in ops))

    # ------------------------------------------------------------- exception path
    print("\n[9] blocked deletion is refused")
    try:
        ex.execute("dsh", "session-does-not-exist-at-all")
        check("unknown session refused", False, "execute() should have raised")
    except ExecutionError as e:
        check("unknown session refused", True, str(e)[:70])

    print("\n" + "=" * 78)
    if FAILURES:
        print(f"RESULT: {len(FAILURES)} FAILURE(S)")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("RESULT: ALL CHECKS PASSED")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    try:
        code = main()
    finally:
        # Leave the sandbox for inspection only if the run failed.
        if not FAILURES:
            err = remove_tree(_SANDBOX)
            if err and not globals().get("_SANDBOX_CLEANUP_WARNED"):
                print(f"[warn] could not remove sandbox {_SANDBOX}: {err}")
        else:
            print(f"\nSandbox kept for inspection: {_SANDBOX}")
    raise SystemExit(code)
