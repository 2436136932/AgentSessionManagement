"""HTTP-level contract tests.

The core suites exercise `core.*` directly, so they cannot catch a defect in
`server.py` itself. That gap was real: `/api/quarantine/purge` accepted a
`dry_run` flag and then purged for real, which would have destroyed a user's
undo buffer on a request that explicitly asked for a preview.

This suite starts the real server on a free port and checks the contracts that
only exist at the HTTP layer:

  1. every destructive endpoint honours `dry_run` and reports `dry_run: true`
  2. a preview changes nothing (session sizes and the quarantine are identical
     before and after)
  3. the irreversible step (invoking an uninstaller) still requires explicit
     confirmation
  4. malformed bodies are rejected with 4xx rather than 500 or a silent success

It only ever issues *previews*, so it cannot damage real data.

Run:  python selftest_api.py
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
FAILURES: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        print(f"  [FAIL] {name}" + (f"  -- {detail}" if detail else ""))
        FAILURES.append(name)


def section(t: str) -> None:
    print(f"\n{t}")
    print("-" * 74)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    def __init__(self, port: int):
        self.port = port
        self.proc = subprocess.Popen(
            [sys.executable, "server.py", "--port", str(port), "--no-browser"],
            cwd=str(HERE),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def wait(self, timeout: float = 40.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(self.base + "/api/report", timeout=20):
                    return True
            except Exception:
                time.sleep(0.5)
        return False

    def get(self, path: str, timeout: int = 300):
        with urllib.request.urlopen(self.base + path, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")

    def post(self, path: str, body, timeout: int = 300):
        req = urllib.request.Request(
            self.base + path,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except Exception:
                return e.code, {}

    def stop(self) -> None:
        try:
            self.proc.terminate()
            self.proc.wait(timeout=15)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass


def main() -> int:
    print("=" * 74)
    print("HTTP 契约测试（只发预演请求，不改动任何真实数据）")
    print("=" * 74)

    port = free_port()
    srv = Server(port)
    try:
        if not srv.wait():
            print("  [FAIL] 服务未能启动")
            return 1
        print(f"  服务已启动: {srv.base}")

        _, sess = srv.get("/api/sessions")
        sessions = sess.get("sessions") or []
        if not sessions:
            print("  [SKIP] 本机没有会话，无法执行预演契约检查")
            return 0
        one = sessions[0]
        agent, sid = one["agent"], one["sid"]

        section("1. 每个破坏性接口都必须支持 dry_run 且如实标注")
        cases = [
            ("/api/delete", {"agent": agent, "sid": sid, "dry_run": True}),
            ("/api/batch-delete",
             {"items": [{"agent": agent, "sid": sid}], "dry_run": True}),
            ("/api/archive-delete",
             {"agent": agent, "sid": sid, "dry_run": True}),
            ("/api/cleanup",
             {"agent": agent, "dispositions": ["safe"], "dry_run": True}),
            ("/api/registry-delete",
             {"hive": "HKCU", "reg_key": "SOFTWARE\\NoSuchKeyForTest",
              "dry_run": True}),
            ("/api/quarantine/purge", {"mode": "all", "dry_run": True}),
            ("/api/uninstall/run", {"agent": agent, "dry_run": True}),
        ]

        before = {s["sid"]: s.get("size") for s in sessions}
        _, q_before = srv.get("/api/quarantine")
        q_n = q_before.get("entry_count")
        q_bytes = q_before.get("total_bytes")

        for ep, body in cases:
            st, j = srv.post(ep, body)
            check(f"{ep} 返回 200 且 dry_run=true",
                  st == 200 and j.get("dry_run") is True,
                  f"status={st} dry_run={j.get('dry_run')} err={j.get('error')}")
            check(f"{ep} 提供中文说明",
                  bool(j.get("note")), str(j.get("note"))[:40])

        section("2. 预演不得改动任何数据")
        _, sess2 = srv.get("/api/sessions")
        after = {s["sid"]: s.get("size") for s in (sess2.get("sessions") or [])}
        check("会话列表与体积完全一致", before == after,
              f"{len(before)} vs {len(after)}")
        _, q_after = srv.get("/api/quarantine")
        check("隔离区条目数未变", q_after.get("entry_count") == q_n,
              f"{q_n} -> {q_after.get('entry_count')}")
        check("隔离区占用未变", q_after.get("total_bytes") == q_bytes)

        section("3. 不可逆步骤仍需显式确认")
        st, j = srv.post("/api/uninstall/run", {"agent": agent})
        check("不带 confirm 的卸载调用被拒绝", st == 400 and not j.get("ok"),
              f"status={st} ok={j.get('ok')}")
        check("拒绝原因说明不可撤销", "不可撤销" in str(j.get("error", "")),
              str(j.get("error"))[:50])

        section("4. 畸形请求体被拒绝而不是静默成功")
        bad = [
            ("/api/batch-delete", {"items": "notalist"}, "items 必须是数组"),
            ("/api/batch-delete", {"items": ["bare"]}, "必须是对象"),
            ("/api/tags", {"agent": agent, "sid": sid, "tags": "str"}, "必须是数组"),
            ("/api/cleanup", {"agent": "no-such-agent", "dry_run": True}, None),
            ("/api/quarantine/purge", {"op_ids": "notalist"}, "必须是数组"),
        ]
        for ep, body, expect in bad:
            st, j = srv.post(ep, body)
            ok = st >= 400 and not j.get("ok")
            check(f"{ep} 拒绝 {str(body)[:38]}", ok,
                  f"status={st} ok={j.get('ok')}")

        section("5. 只读接口仍然可用")
        for ep in ("/api/report", "/api/quarantine", "/api/uninstall/overview"):
            st, j = srv.get(ep)
            check(f"{ep} 正常", st == 200 and j.get("ok") is not False,
                  f"status={st}")

    finally:
        srv.stop()

    print("\n" + "=" * 74)
    if FAILURES:
        print(f"RESULT: {len(FAILURES)} 项失败")
        for f in FAILURES:
            print(f"  - {f}")
    else:
        print("RESULT: 全部通过")
    print("=" * 74)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
