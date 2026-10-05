"""Run every self-test in sequence and summarise.

    python run_all_tests.py

Exit code 0 means all suites passed. These tests never touch real session data:
the delete tests redirect USERPROFILE/APPDATA to a throwaway sandbox. The scan
test is read-only.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

SUITES = [
    ("静态审计 (导入 + 未定义名称 + 未用导入)", "audit_static.py"),
    ("P0 只读扫描 (真实数据, 只读)", "selftest_scan.py"),
    ("会话内容预览 (只读, 逐字节校验)", "selftest_preview.py"),
    ("安全防护: 保留标记 / 指纹校验 / 保留规则", "selftest_safety.py"),
    ("恶意输入防护 (只读, 不删除)", "selftest_hostile.py"),
    ("残留清理: 归属分级 / never 拒绝 / 预演 / 隔离区策略", "selftest_residue.py"),
    ("删除/还原 - DSH 文件与索引", "selftest_delete.py"),
    ("删除/还原 - SQLite、全文索引与 CodeBuddy 层级", "selftest_sqlite.py"),
    ("真实数据库副本往返 (只读原件)", "selftest_realdb.py"),
]


def main() -> int:
    results = []
    for label, script in SUITES:
        print("\n" + "#" * 78)
        print(f"# {label}   ({script})")
        print("#" * 78)
        p = subprocess.run(
            [sys.executable, str(HERE / script)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=900,
        )
        out = p.stdout or ""
        print(out.rstrip())
        if p.stderr and p.stderr.strip():
            # Only surface stderr when something actually failed.
            if p.returncode != 0:
                print("--- stderr ---")
                print(p.stderr.rstrip()[-2000:])
        ok = p.returncode == 0
        results.append((label, ok))
        print(f"\n>>> {'PASS' if ok else 'FAIL'}: {label}")

    print("\n" + "=" * 78)
    print("SUMMARY")
    print("=" * 78)
    for label, ok in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    failed = [l for l, ok in results if not ok]
    print()
    if failed:
        print(f"{len(failed)} suite(s) failed.")
        return 1
    print("All suites passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
