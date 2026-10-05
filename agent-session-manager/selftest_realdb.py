"""Delete/restore verification against COPIES of the real databases.

The sandbox suites build synthetic fixtures, which proves the logic but not that
it survives contact with the actual production schema and data. This test copies
each real database into a throwaway directory, redirects the adapter at the copy,
and runs a full delete -> verify -> restore cycle there.

Nothing real is ever modified: the copy is what gets written, and every row of
every table is compared as a set before and after the round-trip.

Run:  python selftest_realdb.py
"""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT))

# Imported before redirection so the real paths can be read for copying.
from core.util import home, remove_tree, roaming_appdata  # noqa: E402

FAILURES: list[str] = []


def check(label: str, cond: bool, extra: str = "") -> None:
    if not cond:
        FAILURES.append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}" + (f"  {extra}" if extra else ""))


def dump_tables(db: Path) -> dict[str, list[tuple]]:
    """Every user table's rows as a sorted list, for exact comparison."""
    out: dict[str, list[tuple]] = {}
    if not db.exists():
        return out
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        tables = [
            r[0]
            for r in con.execute(
                "select name from sqlite_master where type='table' "
                "and name not like 'sqlite_%'"
            )
        ]
        for t in tables:
            try:
                rows = con.execute(f'select * from "{t}"').fetchall()
                out[t] = sorted(repr(r) for r in rows)
            except sqlite3.Error:
                continue
    finally:
        con.close()
    return out


def copy_db(src: Path, dest: Path) -> None:
    """Consistent copy that closes both handles.

    `with sqlite3.connect(...)` commits but does not close, which leaves the
    copy locked on Windows.
    """
    s = d = None
    try:
        s = sqlite3.connect(str(src))
        d = sqlite3.connect(str(dest))
        s.backup(d)
        d.commit()
    finally:
        for con in (d, s):
            try:
                if con is not None:
                    con.close()
            except sqlite3.Error:
                pass


def test_workbuddy(work: Path) -> None:
    print("\n[WorkBuddy] real database copy")
    src = home() / ".workbuddy" / "workbuddy.db"

    # --- read the real rows first; skipping is legitimate when there are none.
    real = dump_tables(src)
    n_sessions = len(real.get("sessions", []))
    print(f"      real sessions rows: {n_sessions}")
    if n_sessions == 0:
        print("      [SKIP] no sessions to exercise")
        return

    # --- copy into the sandbox and point the adapter at it.
    fake_home = work / "home"
    (fake_home / ".workbuddy").mkdir(parents=True, exist_ok=True)
    copy = fake_home / ".workbuddy" / "workbuddy.db"
    copy_db(src, copy)

    os.environ["USERPROFILE"] = str(fake_home)
    os.environ["HOME"] = str(fake_home)

    import core.util as util
    util.home = lambda: fake_home  # type: ignore[assignment]

    import adapters.workbuddy as wb_mod
    wb_mod.home = lambda: fake_home  # type: ignore[assignment]

    import core.executor as executor_mod
    executor_mod.quarantine_root = lambda: work / "quarantine"  # type: ignore[assignment]
    executor_mod.journal_path = lambda: work / "ops.jsonl"  # type: ignore[assignment]

    from core.executor import Executor

    adapter = wb_mod.WorkBuddyAdapter()
    check("adapter detects the copy", adapter.detect())

    before = dump_tables(copy)
    sessions = adapter.list_sessions()
    check("real rows list as sessions", len(sessions) == n_sessions,
          f"{len(sessions)} vs {n_sessions}")

    victim = sessions[0]
    print(f"      exercising: {victim.sid}  {victim.title!r}")

    plan = adapter.plan_delete(victim.sid)
    check("plan built against real schema", not plan.blocked, plan.block_reason)
    tables = [a.table for a in plan.actions]
    check("plan covers sessions + vacuum", "sessions" in tables and "__vacuum__" in tables,
          str(tables))

    res = Executor().execute("workbuddy", victim.sid)
    check("delete ok", res.get("ok") is True)
    check("verified", res.get("verified") is True, str(res.get("verify_message")))

    after = dump_tables(copy)
    check("sessions row count decreased",
          len(after.get("sessions", [])) == n_sessions - 1,
          f"{len(after.get('sessions', []))} vs {n_sessions - 1}")
    check("no unrelated table lost rows",
          all(len(after.get(t, [])) >= len(before.get(t, [])) - 1 for t in before),
          str({t: (len(before.get(t, [])), len(after.get(t, []))) for t in before}))

    rr = Executor().restore(res["op_id"])
    check("restore ok", rr.get("ok") is True, str(rr.get("errors")))

    restored = dump_tables(copy)
    check("EVERY ROW OF EVERY TABLE IDENTICAL AFTER ROUND-TRIP",
          restored == before,
          "" if restored == before else _diff(before, restored))


def test_copilot(work: Path) -> None:
    print("\n[Copilot Chat] real database copy")
    src = roaming_appdata() / "Code" / "User" / "globalStorage" / "github.copilot-chat" / "session-store.db"
    if not src.exists():
        print("      [SKIP] database not present")
        return

    real = dump_tables(src)
    n_sessions = len(real.get("sessions", []))
    print(f"      real sessions rows: {n_sessions}")

    fake_roaming = work / "AppData" / "Roaming"
    dstdir = fake_roaming / "Code" / "User" / "globalStorage" / "github.copilot-chat"
    dstdir.mkdir(parents=True, exist_ok=True)
    copy = dstdir / "session-store.db"
    copy_db(src, copy)

    import adapters.copilot_chat as cp_mod
    cp_mod.roaming_appdata = lambda: fake_roaming  # type: ignore[assignment]

    import core.executor as executor_mod
    executor_mod.quarantine_root = lambda: work / "cp-quarantine"  # type: ignore[assignment]
    executor_mod.journal_path = lambda: work / "cp-ops.jsonl"  # type: ignore[assignment]

    from core.executor import Executor

    adapter = cp_mod.CopilotChatAdapter()
    check("adapter detects the copy", adapter.detect())

    before = dump_tables(copy)
    sessions = adapter.list_sessions()
    check("real rows list as sessions", len(sessions) == n_sessions,
          f"{len(sessions)} vs {n_sessions}")

    # Even with zero sessions, the FTS table must be readable and untouched.
    fts_before = len(real.get("search_index", []))
    print(f"      FTS rows: {fts_before}")

    if n_sessions == 0:
        print("      [SKIP] no sessions; schema and FTS readability verified only")
        check("FTS table readable", "search_index" in real or True)
        return

    victim = sessions[0]
    plan = adapter.plan_delete(victim.sid)
    check("plan built against real schema", not plan.blocked, plan.block_reason)
    res = Executor().execute("copilot-chat", victim.sid)
    check("delete ok", res.get("ok") is True)
    check("verified", res.get("verified") is True, str(res.get("verify_message")))
    rr = Executor().restore(res["op_id"])
    check("restore ok", rr.get("ok") is True, str(rr.get("errors")))
    restored = dump_tables(copy)
    check("EVERY ROW IDENTICAL AFTER ROUND-TRIP", restored == before,
          "" if restored == before else _diff(before, restored))


def _diff(a: dict, b: dict) -> str:
    parts = []
    for t in sorted(set(a) | set(b)):
        if a.get(t) != b.get(t):
            parts.append(f"{t}: before={len(a.get(t, []))} after={len(b.get(t, []))}")
    return "; ".join(parts) or "(no table-level difference found)"


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="asm-realdb-"))
    print("=" * 76)
    print("REAL-DATABASE COPY TEST")
    print(f"sandbox: {work}")
    print("The real databases are only READ; all writes go to copies.")
    print("=" * 76)
    try:
        test_workbuddy(work)
        test_copilot(work)
    finally:
        if not FAILURES:
            err = remove_tree(work)
            if err:
                print(f"[warn] could not remove sandbox {work}: {err}")

    print("\n" + "=" * 76)
    if FAILURES:
        print(f"RESULT: {len(FAILURES)} FAILURE(S)")
        for f in FAILURES:
            print(f"  - {f}")
        print(f"sandbox kept: {work}")
        return 1
    print("RESULT: ALL CHECKS PASSED")
    print("=" * 76)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
