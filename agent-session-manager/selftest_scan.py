"""Quick self-test of the read-only scan layer (P0).

Run:  python selftest_scan.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core import inventory  # noqa: E402
from core.util import human_size  # noqa: E402


def check_process_detection() -> int:
    """Regression guard for the live-session protection.

    Get-Process reports names without ".exe" while tasklist includes it. When
    the two forms are not unified, every adapter's is_running() silently
    returns empty and the guard that protects a session being written right now
    stops working -- with no error visible anywhere.
    """
    print("\n--- 运行中进程检测（安全防护回归测试） ---")
    from core.util import running_process_names
    from adapters.registry import all_adapters

    names = running_process_names(force=True)
    failed = 0
    if not names:
        print("  [FAIL] 未能获取任何运行中进程")
        return 1

    # Both spellings must be queryable.
    has_bare = any(not n.endswith(".exe") for n in names)
    has_exe = any(n.endswith(".exe") for n in names)
    print(f"  [{'PASS' if has_bare else 'FAIL'}] 存在无扩展名形式")
    print(f"  [{'PASS' if has_exe else 'FAIL'}] 存在 .exe 形式")
    failed += (not has_bare) + (not has_exe)

    # Any adapter whose process is running must actually report it.
    for a in all_adapters():
        running = a.is_running()
        if running:
            print(f"  [PASS] {a.label} 检测到运行中: {', '.join(running)}")
    return failed


def main() -> int:
    print("=" * 78)
    print("P0 SCAN SELF-TEST (read-only, modifies nothing)")
    print("=" * 78)

    failures = check_process_detection()

    rep = inventory.report(force=True)
    print(f"\n检测到 {rep['detected_count']} / {rep['total_supported']} 个已支持的 Agent\n")
    for a in rep["agents"]:
        mark = "OK " if a["installed"] else "-- "
        run = f"  [运行中: {', '.join(a['running'])}]" if a["running"] else ""
        print(
            f"  {mark}{a['label']:<32} "
            f"会话 {str(a['session_count'] or 0):>3}  "
            f"{human_size(a['size']):>9}  "
            f"{a['storage_hint']}{run}"
        )

    sessions = inventory.scan(force=True)
    print(f"\n{'agent':<16}{'sid':<46}{'size':>9}  title")
    print("-" * 110)
    for s in sorted(sessions, key=lambda x: (x.agent, -(x.size or 0))):
        flags = []
        if s.is_ghost:
            flags.append("GHOST")
        if s.is_orphan:
            flags.append("ORPHAN")
        if not s.deletable:
            flags.append("NO-DELETE")
        flag = ("[" + ",".join(flags) + "] ") if flags else ""
        sid = s.sid if len(s.sid) <= 44 else s.sid[:41] + "..."
        title = (s.title or "")[:34]
        print(f"{s.agent:<16}{sid:<46}{human_size(s.size):>9}  {flag}{title}")

    print(f"\n总会话数：{len(sessions)}")

    print("\n--- 清理建议 (health) ---")
    findings = inventory.health(force=True)
    if not findings:
        print("  （无）")
    for f in findings:
        print(f"  [{f['level']:<4}] {f['agent']:<12} {f['title']}   {human_size(f['size'])}")

    print("\n--- 可回收（非会话，仅建议） ---")
    for r in inventory.reclaimable():
        print(f"  {human_size(r['size']):>9}  {r['label']}")
        print(f"             {r['path']}")

    print("\n未支持的已安装程序：")
    for u in rep["unsupported_programs"]:
        print(f"  - {u['name']} {u['version']}")

    if failures:
        print(f"\nRESULT: {failures} 项安全防护检查失败")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
