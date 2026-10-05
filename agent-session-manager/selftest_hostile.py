"""Hostile-input regression test for every adapter.

The single most important safety property of this tool is that no crafted
session id can make an adapter plan a change outside its own data directory.
This drives every adapter with a set of traversal / malformed ids and asserts:

  * every planned path stays inside the adapter's declared roots, and
  * planning never raises and never modifies anything.

Runs against the real adapters with real roots (read-only: plan_delete() does
not write). No session is deleted.

Run:  python selftest_hostile.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from adapters.registry import all_adapters  # noqa: E402
from core.executor import Executor  # noqa: E402

#: Ids that must never produce an out-of-root action.
HOSTILE = [
    "../../etc/passwd",
    r"..\..\Windows\System32",
    r"C:\Windows\System32",
    "C:/Windows/System32",
    "a/b",
    "a\\b",
    ".",
    "..",
    "",
    "x" * 300,
    "sid\x00null",
    "~/.ssh/id_rsa",
    "%USERPROFILE%/.ssh",
    "session-1/../../other",
    r"\\server\share\evil",
    "con",
    "sid:stream",
    "sid*glob",
    "sid?mark",
    'sid"quote',
    "sid<angle>",
    "sid|pipe",
    " sid-space ",
    "\u202e_reversed",
]


def main() -> int:
    print("=" * 76)
    print("HOSTILE-INPUT REGRESSION TEST (read-only: plans only, deletes nothing)")
    print("=" * 76)

    failures: list[str] = []
    adapters = all_adapters()

    for a in adapters:
        roots = [Path(r) for r in a.roots()]
        installed = a.detect()
        print(f"\n{a.label}  (id={a.id})")
        print(f"  installed: {installed}")
        print(f"  roots: {[str(r) for r in roots]}")

        leaks: list[str] = []
        crashes: list[str] = []

        for sid in HOSTILE:
            try:
                plan = a.plan_delete(sid)
            except Exception as e:  # a hostile id must not crash the adapter
                crashes.append(f"{sid!r}: {type(e).__name__}: {e}")
                continue

            for act in list(plan.actions) + list(plan.optional_actions):
                target = act.path or act.db_path or act.json_pointer
                if not target:
                    continue
                # Both defences must hold: the executor's validator must accept
                # nothing out of root, and the raw path must be inside a root.
                import copy as _copy

                probe = _copy.copy(plan)
                probe.actions = [act]
                probe.optional_actions = []
                if Executor.validate(probe, a) == []:
                    leaks.append(f"{sid!r} -> validator accepted {target}")
                if not _within(target, roots):
                    leaks.append(f"{sid!r} -> out-of-root action {target}")

        if crashes:
            failures.extend(f"{a.id}: crash {c}" for c in crashes)
            for c in crashes:
                print(f"  [FAIL] crashed: {c}")
        else:
            print(f"  [PASS] {len(HOSTILE)} hostile ids planned without crashing")

        if leaks:
            failures.extend(f"{a.id}: leak {x}" for x in leaks)
            for x in leaks:
                print(f"  [FAIL] escape: {x}")
        else:
            print(f"  [PASS] no out-of-root action for any hostile id")

    print("\n" + "=" * 76)
    if failures:
        print(f"RESULT: {len(failures)} FAILURE(S)")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("RESULT: ALL CHECKS PASSED")
    print("=" * 76)
    return 0


def _within(target: str, roots: list[Path]) -> bool:
    import os

    try:
        t = os.path.normcase(os.path.normpath(str(Path(target).resolve())))
    except (OSError, ValueError):
        return False
    for r in roots:
        try:
            rn = os.path.normcase(os.path.normpath(str(Path(r).resolve())))
        except (OSError, ValueError):
            continue
        if t == rn or t.startswith(rn + os.sep):
            return True
    return False


if __name__ == "__main__":
    raise SystemExit(main())
