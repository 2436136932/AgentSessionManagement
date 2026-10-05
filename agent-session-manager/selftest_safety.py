"""Tests for the review-to-confirm safety features.

Covers three protections that all exist to stop a *stale* or *unintended*
deletion, and which are easy to get subtly wrong:

  1. pin / keep protection  -- a deliberate "do not delete" must be honoured
                               even for a bulk delete, and must be overridable
                               only explicitly
  2. fingerprint revalidation -- if the session changes between the plan the
     user read and the confirmation, the delete must be refused
  3. retention proposals    -- rules must annotate *why* each candidate matched,
                               and must never propose a pinned session

Runs in a sandbox: USERPROFILE/APPDATA are redirected before adapters load.

Run:  python selftest_safety.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

_SANDBOX = Path(tempfile.mkdtemp(prefix="asm-safe-"))
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

from core.util import home, remove_tree  # noqa: E402

import core.util as util  # noqa: E402

util.data_root = lambda: _SANDBOX / "app" / "_data"  # type: ignore[assignment]
util.quarantine_root = lambda: _SANDBOX / "app" / "_data" / "quarantine"  # type: ignore[assignment]
util.journal_path = lambda: _SANDBOX / "app" / "_data" / "ops.jsonl"  # type: ignore[assignment]
(_SANDBOX / "app" / "_data").mkdir(parents=True, exist_ok=True)

import core.executor as executor_mod  # noqa: E402

executor_mod.quarantine_root = util.quarantine_root  # type: ignore[assignment]
executor_mod.journal_path = util.journal_path  # type: ignore[assignment]

from core.executor import ExecutionError, Executor, plan_fingerprint  # noqa: E402

FAILURES: list[str] = []


def check(label: str, cond: bool, extra: str = "") -> None:
    if not cond:
        FAILURES.append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}" + (f"  {extra}" if extra else ""))


SID_A = "session-aaaa1111-1111-1111-1111-111111111111"
SID_B = "session-bbbb2222-2222-2222-2222-222222222222"
DSH_WS = home() / ".dsh" / "sessions" / "--C-Users-test--"
OLD_TS = 1790000000.0


def build() -> None:
    from compression import zstd

    cache = home() / ".dsh" / "storages" / "session_projcache" / "sessions"
    cache.mkdir(parents=True, exist_ok=True)

    for sid, title in ((SID_A, "重要会话"), (SID_B, "普通会话")):
        d = DSH_WS / sid
        d.mkdir(parents=True, exist_ok=True)
        body = "\n".join([
            json.dumps({"type": "session", "version": 4, "id": sid,
                        "createdAt": 1790000000000, "cwd": "C:\\Users\\test"}),
            json.dumps({"type": "user/message", "seq": 1, "time": 1790000001000,
                        "data": {"content": [{"type": "text", "text": "hi"}]}}),
            json.dumps({"type": "assistant/message", "seq": 2, "time": 1790000002000,
                        "data": {"message": {"role": "assistant", "content": [
                            {"type": "text", "text": "hello"}]}}}),
        ])
        f = d / "session.v4.jsonl.zstd"
        f.write_bytes(zstd.compress(body.encode()))
        os.utime(f, (OLD_TS, OLD_TS))
        os.utime(d, (OLD_TS, OLD_TS))
        cf = cache / f"{sid}.json"
        cf.write_text(json.dumps({
            "version": 7,
            "record": {"identity": {"formatVersion": 4, "createdAt": 1790000000000,
                                    "cwd": "C:\\Users\\test"},
                       "rows": {"title": {"ver": 1, "seq": 1, "val": title}}},
        }, ensure_ascii=False), encoding="utf-8")
        os.utime(cf, (OLD_TS, OLD_TS))

    ws = home() / ".dsh" / "storages" / "workspace.json"
    ws.parent.mkdir(parents=True, exist_ok=True)
    ws.write_text(json.dumps({
        "unit": {"name": "workspace", "version": 2},
        "global": {"workspaceIds": ["w1"], "archivedSessionIds": [], "pinnedSessionIds": []},
        "tables": {"workspaces": {"w1": {"path": "C:\\Users\\test", "title": "t",
                                         "sessionIds": [SID_A, SID_B]}}},
    }), encoding="utf-8")
    for p in (ws, ws.parent):
        try:
            os.utime(p, (OLD_TS, OLD_TS))
        except OSError:
            pass


def main() -> int:
    print("=" * 76)
    print("SAFETY TEST: pin / fingerprint / retention")
    print(f"sandbox: {_SANDBOX}")
    print("=" * 76)
    build()

    from adapters.dsh import DshAdapter
    from core import retention, store

    a = DshAdapter()
    ex = Executor()

    # ================================================== pin / keep protection
    print("\n[1] pin protection")
    check("nothing pinned initially", not store.is_pinned("dsh", SID_A))
    store.pin("dsh", SID_A, "重要会话，别删")
    check("pin recorded", store.is_pinned("dsh", SID_A))
    check("pin reason stored",
          (store.pin_info("dsh", SID_A) or {}).get("reason") == "重要会话，别删")

    try:
        ex.execute("dsh", SID_A)
        check("pinned session delete REFUSED", False, "delete succeeded!")
    except ExecutionError as e:
        check("pinned session delete REFUSED", "保留" in str(e), str(e)[:60])
    check("pinned session still on disk", (DSH_WS / SID_A).is_dir())

    print("\n[2] unpinned sibling is deletable, and pin survives other deletes")
    res = ex.execute("dsh", SID_B)
    check("unpinned session deleted", res.get("ok") is True)
    check("unpinned session gone", not (DSH_WS / SID_B).exists())
    check("pin unaffected by the other delete", store.is_pinned("dsh", SID_A))
    ex.restore(res["op_id"])
    check("restored", (DSH_WS / SID_B).is_dir())

    print("\n[3] explicit override is the only way past a pin")
    over = ex.execute("dsh", SID_A, allow_unpin=True)
    check("override deletes", over.get("ok") is True)
    check("gone after override", not (DSH_WS / SID_A).exists())
    ex.restore(over["op_id"])
    check("restored after override", (DSH_WS / SID_A).is_dir())
    check("pin still set (override does not silently unpin)",
          store.is_pinned("dsh", SID_A))

    print("\n[4] unpin restores deletability")
    store.unpin("dsh", SID_A)
    check("unpinned", not store.is_pinned("dsh", SID_A))
    plan = a.plan_delete(SID_A)
    check("no pin refusal once unpinned", ex.check_pinned(plan) == "")

    # ================================================== fingerprint
    print("\n[5] fingerprint is stable for unchanged data")
    p1 = a.plan_delete(SID_A)
    f1 = plan_fingerprint(p1)
    check("same data -> same fingerprint", plan_fingerprint(a.plan_delete(SID_A)) == f1)
    check("fingerprint is a hex digest", len(f1) == 64 and all(c in "0123456789abcdef" for c in f1))

    print("\n[6] a write between review and confirm is detected")
    target = DSH_WS / SID_A / "session.v4.jsonl.zstd"
    original = target.read_bytes()
    # Append an event and backdate it, so ONLY the content differs and the
    # live-session guard (10-minute recency) does not mask the fingerprint.
    from compression import zstd

    raw = zstd.decompress(original).decode()
    raw += "\n" + json.dumps({"type": "user/message", "seq": 3,
                              "time": 1790000003000,
                              "data": {"content": [{"type": "text",
                                                    "text": "changed!"}]}})
    target.write_bytes(zstd.compress(raw.encode()))
    os.utime(target, (OLD_TS, OLD_TS))
    os.utime(target.parent, (OLD_TS, OLD_TS))

    f2 = plan_fingerprint(a.plan_delete(SID_A))
    check("fingerprint changed after the write", f1 != f2, f"{f1[:10]} -> {f2[:10]}")

    try:
        ex.execute("dsh", SID_A, expected_fingerprint=f1)
        check("stale confirmation REFUSED", False, "delete succeeded with a stale fingerprint")
    except ExecutionError as e:
        check("stale confirmation REFUSED", "指纹" in str(e), str(e).splitlines()[0][:70])
    check("session untouched after refusal", (DSH_WS / SID_A).is_dir())

    print("\n[7] a fresh fingerprint goes through")
    fresh = plan_fingerprint(a.plan_delete(SID_A))
    ok = ex.execute("dsh", SID_A, expected_fingerprint=fresh)
    check("fresh fingerprint deletes", ok.get("ok") is True)
    ex.restore(ok["op_id"])
    check("restored", (DSH_WS / SID_A).is_dir())

    print("\n[8] an empty fingerprint skips the check (backwards compatible)")
    ok2 = ex.execute("dsh", SID_A, expected_fingerprint="")
    check("empty fingerprint allowed", ok2.get("ok") is True)
    ex.restore(ok2["op_id"])

    # ================================================== retention
    print("\n[9] retention rules annotate reasons and respect pins")
    from core import inventory

    sessions = [s.to_dict() for s in inventory.scan(force=True)]
    check("sessions scanned", len(sessions) >= 2, str(len(sessions)))
    store.pin("dsh", SID_A, "保留中")
    sessions = [s.to_dict() for s in inventory.scan(force=True)]
    store.decorate(sessions)
    pinned_now = [s for s in sessions if s["sid"] == SID_A][0]
    check("decorate marks pinned", pinned_now.get("pinned") is True)

    r = retention.evaluate(sessions, rules=["old", "small"], days=1, max_kb=999999)
    check("proposals produced", r["proposal_count"] >= 1, str(r["proposal_count"]))
    check("every proposal carries a reason",
          all(p["reasons"] for p in r["proposals"]))
    ids = [p["sid"] for p in r["proposals"]]
    check("PINNED session is NOT proposed", SID_A not in ids, str(ids))
    check("pinned session reported as skipped", r["skipped_count"] >= 1,
          str(r["skipped_count"]))
    check("skipped entry explains why",
          all("保留" in (s.get("skipped") or "") for s in r["skipped_pinned"]))

    print("\n[10] retention is advisory only")
    before_files = sorted(p.name for p in DSH_WS.iterdir())
    retention.evaluate(sessions, rules=["ghost", "orphan", "old", "small",
                                        "oversized", "unread"], days=0)
    after_files = sorted(p.name for p in DSH_WS.iterdir())
    check("evaluating rules deleted nothing", before_files == after_files)

    print("\n[11] state store round-trips tags and notes")
    store.set_tags("dsh", SID_A, ["重要", "参考", "重要"])
    check("tags deduped and sorted",
          store.get_tags("dsh", SID_A) == ["参考", "重要"], str(store.get_tags("dsh", SID_A)))
    store.set_note("dsh", SID_A, "这是备注")
    check("note round-trips", store.get_note("dsh", SID_A) == "这是备注")
    check("counts reported", store.counts()["pins"] >= 1)
    store.set_tags("dsh", SID_A, [])
    check("tags cleared", store.get_tags("dsh", SID_A) == [])

    # ================================================== workspace-level keep
    print("\n[12] workspace-level protection covers descendants and new sessions")
    store.unpin("dsh", SID_A)
    store.pin_workspace("dsh", "C:\\Users\\test", "整个项目都要保留")
    check("workspace pin recorded", len(store.workspace_pins()) == 1, str(store.workspace_pins()))

    # An existing session inside the folder is covered...
    check("existing session matches workspace pin",
          store.match_workspace("dsh", "C:\\Users\\test") is not None)
    # ...as is a nested subfolder...
    check("nested subfolder also matches",
          store.match_workspace("dsh", "C:\\Users\\test\\sub\\deep") is not None)
    # ...and a folder that does not exist yet (the "future sessions" promise).
    check("future session folder matches (rule is path-based, not id-based)",
          store.match_workspace("dsh", "C:\\Users\\test\\brand-new") is not None)
    # Trailing separator and case differences must not defeat it.
    check("trailing separator tolerated",
          store.match_workspace("dsh", "C:\\Users\\test\\") is not None)
    check("case differences tolerated",
          store.match_workspace("dsh", "c:\\users\\TEST") is not None)
    # A different folder must NOT match.
    check("unrelated folder does not match",
          store.match_workspace("dsh", "C:\\Other\\place") is None)
    # A sibling with a shared prefix must NOT match (guards against naive str.startswith).
    check("sibling with shared prefix does not match",
          store.match_workspace("dsh", "C:\\Users\\test2") is None,
          "'test2' must not be treated as inside 'test'")

    sessions = [s.to_dict() for s in inventory.scan(force=True)]
    store.decorate(sessions)
    covered = [s for s in sessions if s.get("workspace_protected")]
    check("decorate flags workspace-protected sessions", len(covered) >= 1, str(len(covered)))
    check("flagged session reports the pin path",
          all(s.get("workspace_pin_path") for s in covered))

    print("\n[13] workspace protection blocks deletion of an unpinned member")
    member = next(s for s in sessions if s.get("workspace_protected") and not s.get("pinned"))
    try:
        ex.execute("dsh", member["sid"])
        check("workspace-protected delete REFUSED", False, "delete succeeded!")
    except ExecutionError as e:
        check("workspace-protected delete REFUSED", "工作区" in str(e), str(e)[:70])
    check("still on disk", (DSH_WS / member["sid"]).is_dir())

    print("\n[14] explicit override also lifts workspace protection")
    over = ex.execute("dsh", member["sid"], allow_unpin=True)
    check("override works for workspace pin", over.get("ok") is True)
    ex.restore(over["op_id"])
    check("restored", (DSH_WS / member["sid"]).is_dir())
    check("workspace pin still set", len(store.workspace_pins()) == 1)

    print("\n[15] retention skips workspace-protected sessions too")
    sessions = [s.to_dict() for s in inventory.scan(force=True)]
    store.decorate(sessions)
    r2 = retention.evaluate(sessions, rules=["old", "small"], days=1, max_kb=999999)
    ws_ids = {s["sid"] for s in sessions if s.get("workspace_protected")}
    check("workspace-protected sessions are not proposed",
          not (ws_ids & {p["sid"] for p in r2["proposals"]}),
          f"protected={len(ws_ids)} proposals={r2['proposal_count']}")
    check("they are reported as skipped instead", r2["skipped_count"] >= len(ws_ids),
          str(r2["skipped_count"]))
    check("skip reason names the workspace",
          any("工作区" in (s.get("skipped") or "") for s in r2["skipped_pinned"]))

    print("\n[16] unpinning the workspace restores deletability")
    store.unpin_workspace("dsh", "C:\\Users\\test")
    check("workspace pin cleared", len(store.workspace_pins()) == 0)
    sessions = [s.to_dict() for s in inventory.scan(force=True)]
    store.decorate(sessions)
    check("no session still workspace-protected",
          not any(s.get("workspace_protected") for s in sessions))
    check("no session protected at all",
          not any(s.get("protected") for s in sessions))

    print("\n" + "=" * 76)
    if FAILURES:
        print(f"RESULT: {len(FAILURES)} FAILURE(S)")
        for f in FAILURES:
            print(f"  - {f}")
        print(f"sandbox kept: {_SANDBOX}")
        return 1
    print("RESULT: ALL CHECKS PASSED")
    print("=" * 76)
    return 0


if __name__ == "__main__":
    try:
        code = main()
    finally:
        if not FAILURES:
            err = remove_tree(_SANDBOX)
            if err:
                print(f"[warn] could not remove sandbox {_SANDBOX}: {err}")
    raise SystemExit(code)
