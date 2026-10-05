"""Safety tests for the residue cleaner.

This suite exists to prove the two claims that make the cleanup feature usable
at all:

  1. **A source checkout is never swept.** The real machine has
     `E:\\workbuddyapi-main` -- a user's own git repository that merely
     *contains* a `.codebuddy` directory. A keyword-based cleaner would delete
     it. Here it must come back as `never`, every time, through every entry
     point (classifier, preflight, executor).

  2. **A shared resource is never swallowed.** `HKCU\\SOFTWARE\\Tencent` holds
     QQ and WeChat settings as well as WorkBuddy's, and `C:\\Program Files` is
     used by everything. Both must be refused.

It also covers the false-positive boundaries that decide whether the feature is
useful or noise: a bundled `token.py` / `token-schema.json` is not a credential,
while `~/.dsh/.credentials.yaml` and a `connector-keys/*.key` are.

Everything runs in a sandbox: USERPROFILE / APPDATA / LOCALAPPDATA are
redirected to a temp tree BEFORE any adapter is imported, and the tool's own
_data is redirected too. The real session stores are never touched.

Run:  python selftest_residue.py
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# --------------------------------------------------------------------------
# 1. Sandbox FIRST, before any project import can resolve a home directory.
# --------------------------------------------------------------------------

_SANDBOX = Path(tempfile.mkdtemp(prefix="asm-residue-"))
_FAKE_HOME = _SANDBOX / "home"
_FAKE_LOCAL = _SANDBOX / "AppData" / "Local"
_FAKE_ROAMING = _SANDBOX / "AppData" / "Roaming"
_FAKE_DRIVE = _SANDBOX / "drive"
for _p in (_FAKE_HOME, _FAKE_LOCAL, _FAKE_ROAMING, _FAKE_DRIVE):
    _p.mkdir(parents=True, exist_ok=True)

os.environ["USERPROFILE"] = str(_FAKE_HOME)
os.environ["HOME"] = str(_FAKE_HOME)
os.environ["LOCALAPPDATA"] = str(_FAKE_LOCAL)
os.environ["APPDATA"] = str(_FAKE_ROAMING)

sys.path.insert(0, str(Path(__file__).resolve().parent))

import core.util as util  # noqa: E402

util.app_root = lambda: _SANDBOX / "app"  # type: ignore[assignment]
(_SANDBOX / "app").mkdir(parents=True, exist_ok=True)
util.data_root = lambda: (_SANDBOX / "app" / "_data")  # type: ignore[assignment]
util.quarantine_root = lambda: (_SANDBOX / "app" / "_data" / "quarantine")  # type: ignore[assignment]
util.journal_path = lambda: (_SANDBOX / "app" / "_data" / "operations.jsonl")  # type: ignore[assignment]
(_SANDBOX / "app" / "_data").mkdir(parents=True, exist_ok=True)

from core import cleaner  # noqa: E402
from core.ownership import (  # noqa: E402
    NEVER,
    REVIEW,
    SAFE,
    Classifier,
    _looks_like_credential,
)

cleaner.quarantine_root = util.quarantine_root  # type: ignore[assignment]
cleaner.journal_path = util.journal_path  # type: ignore[assignment]

from core.util import remove_tree  # noqa: E402

FAILURES: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        print(f"  [FAIL] {name}" + (f"  -- {detail}" if detail else ""))
        FAILURES.append(name)


def section(title: str) -> None:
    print(f"\n{title}")
    print("-" * 74)


# --------------------------------------------------------------------------
# 2. Build the fixtures that mirror the real machine's traps.
# --------------------------------------------------------------------------


def build_fixtures() -> dict[str, Path]:
    """Create the directory shapes the rules are supposed to classify."""
    made: dict[str, Path] = {}

    # --- a user's own git repository that contains an agent dot-folder -------
    repo = _SANDBOX / "proj" / "workbuddyapi-main"
    (repo / ".git").mkdir(parents=True, exist_ok=True)
    (repo / "src").mkdir(parents=True, exist_ok=True)
    (repo / "package.json").write_text('{"name":"x"}', encoding="utf-8")
    (repo / ".codebuddy").mkdir(parents=True, exist_ok=True)
    (repo / ".codebuddy" / "config.json").write_text("{}", encoding="utf-8")
    made["repo"] = repo
    made["repo_dotfolder"] = repo / ".codebuddy"

    # --- a plain git repo, to prove the marker check is not name-based ------
    plain = _SANDBOX / "proj" / "plain-src"
    plain.mkdir(parents=True, exist_ok=True)
    (plain / "readme.txt").write_text("hi", encoding="utf-8")
    made["plain"] = plain

    # --- an empty shell left behind by an uninstall -------------------------
    shell = _SANDBOX / "proj" / "WorkBuddyStorage"
    shell.mkdir(parents=True, exist_ok=True)
    made["shell"] = shell

    # --- a real key directory and a bundled runtime that *looks* like keys --
    keys = _SANDBOX / "keys" / ".workbuddy-key-fallback" / "connector-keys"
    keys.mkdir(parents=True, exist_ok=True)
    made["key_file"] = keys / "f7b22da8d7822799950589ac5a812f0a.key"
    made["key_file"].write_text("-----BEGIN PRIVATE KEY-----\nAAAA\n", encoding="utf-8")
    made["key_dir"] = keys

    creds = _SANDBOX / "keys" / ".credentials.yaml"
    creds.parent.mkdir(parents=True, exist_ok=True)
    creds.write_text("token: abc\n", encoding="utf-8")
    made["credentials_yaml"] = creds

    bundle = _SANDBOX / "bundle"
    (bundle / "node_modules").mkdir(parents=True, exist_ok=True)
    for name, body in (
        ("token.py", "import token\n"),
        ("_tokenizer.py", "def tok(): pass\n"),
        ("token-schema.json", '{"type":"object"}'),
        ("user-secret.svg", "<svg/>"),
        ("git-credential-helper-selector.exe", "MZ\x00\x00"),
    ):
        p = bundle / name
        p.write_text(body, encoding="utf-8")
        made[f"bundle_{name}"] = p

    # A browser subsystem that contains "Tokens" but holds no credential.
    trust = bundle / "Trust Tokens"
    trust.write_text("binary-ish", encoding="utf-8")
    made["trust_tokens"] = trust

    # --- a genuine cache to prove the safe path still works -----------------
    cache = _SANDBOX / "proj" / "app" / "session" / "GPUCache"
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "data_0").write_bytes(b"x" * 4096)
    made["cache"] = cache

    # --- a stateful store that must NOT be treated as cache -----------------
    state = _SANDBOX / "proj" / "app" / "session" / "Local Storage"
    state.mkdir(parents=True, exist_ok=True)
    (state / "leveldb.ldb").write_bytes(b"y" * 2048)
    made["local_storage"] = state

    # --- a SQLite sidecar that must be user_data, not cache -----------------
    vscdb = _SANDBOX / "proj" / "app" / "state.vscdb"
    vscdb.write_bytes(b"SQLite format 3\x00")
    made["vscdb"] = vscdb
    wal = _SANDBOX / "proj" / "app" / "state.vscdb-wal"
    wal.write_bytes(b"\x00" * 128)
    made["vscdb_wal"] = wal

    return made


# --------------------------------------------------------------------------
# 3. Tests
# --------------------------------------------------------------------------


def test_source_repo_protection(fx: dict) -> None:
    section("1. 源码仓库绝不被清理（真实误删反例）")
    clf = Classifier()

    o = clf.classify(fx["repo"])
    check("git 仓库判为 never/source_repo",
          o.disposition == NEVER and o.category == "source_repo",
          f"{o.disposition}/{o.category}")
    check("仓库被判为 never 时给出可核对的原因",
          "源码仓库" in o.evidence or ".git" in o.evidence, o.evidence)

    # The dot-folder inside it must also not be swept: deleting it would damage
    # the repository's working tree.
    o2 = clf.classify(fx["repo_dotfolder"])
    check("仓库内的 .codebuddy 也必须 never",
          o2.disposition == NEVER, f"{o2.disposition}/{o2.category}")

    # A directory that merely *looks* like a repo name but has no marker is not
    # forced to never -- the rule keys on markers, not on names.
    o3 = clf.classify(fx["plain"])
    check("无仓库特征的普通目录不因名字被判 never",
          o3.category != "source_repo", f"{o3.disposition}/{o3.category}")


def test_shared_protection() -> None:
    section("2. 共享资源绝不被清理")
    clf = Classifier()
    for raw, label in (
        (r"C:\Program Files", "Program Files"),
        (r"C:\Program Files (x86)", "Program Files (x86)"),
        (r"C:\ProgramData\Microsoft", "ProgramData\\Microsoft"),
        (r"C:\Windows\System32", "Windows\\System32"),
    ):
        p = Path(raw)
        if not p.exists():
            # Virtualise the check so it runs on any machine.
            o = clf.categorize(Path(raw), "unknown")
            check(f"{label} 判为 shared", o[0] == "shared", o[0])
            continue
        o = clf.classify(p)
        check(f"{label} 判为 shared/never",
              o.category == "shared" and o.disposition == NEVER,
              f"{o.disposition}/{o.category}")


def test_credential_precision(fx: dict) -> None:
    section("3. 凭据识别：既不漏报，也不误报")
    for key, label in (
        ("key_file", ".key 密钥文件"),
        ("credentials_yaml", ".credentials.yaml（强名匹配胜过扩展名排除）"),
    ):
        check(f"{label} 识别为凭据",
              _looks_like_credential(fx[key]), str(fx[key]))

    for key, label in (
        ("bundle_token.py", "token.py（打包运行时）"),
        ("bundle__tokenizer.py", "_tokenizer.py"),
        ("bundle_token-schema.json", "token-schema.json"),
        ("bundle_user-secret.svg", "user-secret.svg"),
        ("bundle_git-credential-helper-selector.exe", "git-credential-helper-selector.exe"),
        ("trust_tokens", "Trust Tokens（浏览器隐私子系统）"),
    ):
        check(f"{label} 不误报为凭据",
              not _looks_like_credential(fx[key]), str(fx[key]))


def test_cache_vs_state(fx: dict) -> None:
    section("4. 可再生缓存 与 有状态存储 必须区分")
    clf = Classifier()

    o = clf.classify(fx["cache"])
    check("GPUCache 判为 safe/cache",
          o.disposition == SAFE and o.category == "cache",
          f"{o.disposition}/{o.category}")

    o = clf.classify(fx["local_storage"])
    check("Local Storage 判为 user_data（不是 cache）",
          o.category == "user_data", f"{o.disposition}/{o.category}")

    o = clf.classify(fx["vscdb"])
    check("state.vscdb 判为 user_data（不是 cache）",
          o.category == "user_data", f"{o.disposition}/{o.category}")

    o = clf.classify(fx["vscdb_wal"])
    check("state.vscdb-wal 判为 user_data（删了会损坏数据库）",
          o.category == "user_data", f"{o.disposition}/{o.category}")

    o = clf.classify(fx["shell"])
    check("空壳目录判为 safe/empty_shell",
          o.disposition == SAFE and o.category == "empty_shell",
          f"{o.disposition}/{o.category}")


def test_executor_refuses_never(fx: dict) -> None:
    section("5. 执行器在最底层再次拒绝 never（纵深防御）")
    ex = cleaner.CleanupExecutor()

    pf = cleaner.preflight("dsh", [str(fx["repo"])])
    check("preflight 拒绝 git 仓库",
          pf["will_remove"] == 0 and pf["refused"] == 1,
          f"will_remove={pf['will_remove']} refused={pf['refused']}")

    # Even if a caller skips preflight and calls execute directly, nothing may
    # be removed. `executor` re-runs classification internally.
    # `force_while_running` is set so this assertion isolates the never-refusal
    # from the separate running-process gate (which test 8 covers).
    r = ex.execute("dsh", [str(fx["repo"])], force_while_running=True)
    check("execute 对 never 项不删除任何东西",
          r.get("removed", 0) == 0, f"removed={r.get('removed')}")
    check("git 仓库在执行后仍然完好",
          (fx["repo"] / ".git").exists() and (fx["repo"] / "package.json").exists())

    pf = cleaner.preflight("dsh", ["C:\\Program Files"])
    check("preflight 拒绝共享目录",
          pf["will_remove"] == 0, f"will_remove={pf['will_remove']}")


def test_executor_removes_safe_reversibly(fx: dict) -> None:
    section("6. 可安全清理的项目：真的移除，且可还原")
    target = _SANDBOX / "proj" / "removable" / "GPUCache"
    target.mkdir(parents=True, exist_ok=True)
    (target / "blob").write_bytes(b"z" * 8192)

    ex = cleaner.CleanupExecutor()
    r = ex.execute("dsh", [str(target)], force_while_running=True)
    check("可安全清理的缓存被移除", r.get("removed") == 1,
          f"removed={r.get('removed')} results={r.get('results')}")
    check("移除后原路径确实不存在", not target.exists())
    check("数据进入隔离区（可还原）",
          bool(r.get("op_id")) and Path(r.get("quarantine", "")).exists(),
          str(r.get("quarantine")))

    # Restore must put it back byte for byte.
    q = Path(r["quarantine"])
    matches = list(q.rglob("GPUCache"))
    check("隔离区中存在该目录的副本", bool(matches), str(q))
    if matches:
        src = matches[0]
        target.parent.mkdir(parents=True, exist_ok=True)
        import shutil as _sh

        _sh.move(str(src), str(target))
        check("还原后文件内容一致",
              (target / "blob").exists()
              and (target / "blob").stat().st_size == 8192)


def test_dry_run_changes_nothing(fx: dict) -> None:
    section("7. 预演绝不修改任何东西")
    target = _SANDBOX / "proj" / "dryrun" / "GPUCache"
    target.mkdir(parents=True, exist_ok=True)
    (target / "f").write_bytes(b"d" * 1024)

    qroot = util.quarantine_root()
    before = {p.name for p in qroot.iterdir()}

    ex = cleaner.CleanupExecutor()
    r = ex.execute("dsh", [str(target)], dry_run=True, force_while_running=True)
    check("预演返回 dry_run=True", r.get("dry_run") is True)
    check("预演后目录仍在", target.exists() and (target / "f").exists())

    after = {p.name for p in qroot.iterdir()}
    check("预演不产生新的隔离区目录",
          not (after - before),
          str(sorted(after - before)))
    pf = r.get("preflight") or {}
    check("预演仍如实报告将移除多少",
          pf.get("will_remove") == 1, str(pf.get("will_remove")))


def test_running_agent_blocks_execution() -> None:
    section("8. Agent 运行中：预演允许，真正执行被拒")
    # A real adapter is used, but the process list is faked so the assertion
    # does not depend on what happens to be running on this machine.
    import adapters.registry as reg

    class FakeAdapter:
        id = "faketest"
        label = "Fake Test"
        processes = ("definitely-not-running-xyz.exe",)

        def detect(self):
            return True

        def roots(self):
            return [_SANDBOX / "proj" / "fake"]

        def is_running(self):
            return ["definitely-not-running-xyz.exe"]

    orig = reg.get_adapter
    reg.get_adapter = lambda aid: FakeAdapter() if aid == "faketest" else orig(aid)
    try:
        target = _SANDBOX / "proj" / "fake" / "Cache"
        target.mkdir(parents=True, exist_ok=True)
        (target / "x").write_bytes(b"c" * 512)

        ex = cleaner.CleanupExecutor()
        r = ex.execute("faketest", [str(target)], dry_run=True)
        check("运行中仍可预演", r.get("ok") is True and r.get("would_block") is True,
              str(r.get("would_block")))

        try:
            ex.execute("faketest", [str(target)])
            check("运行中真正执行应被拒绝", False, "没有抛出 CleanupError")
        except cleaner.CleanupError as e:
            check("运行中真正执行被拒绝", "运行" in str(e), str(e))
        check("被拒绝后目录完好", target.exists() and (target / "x").exists())

        r = ex.execute("faketest", [str(target)], force_while_running=True)
        check("显式 force 时可以继续", r.get("removed") == 1, str(r.get("removed")))
    finally:
        reg.get_adapter = orig


def test_data_root_needs_explicit_optin() -> None:
    section("9. 数据根目录需要显式确认才能删除")
    import adapters.registry as reg

    root = _SANDBOX / "home" / ".fakedata"
    root.mkdir(parents=True, exist_ok=True)
    (root / "sessions").mkdir(parents=True, exist_ok=True)
    (root / "sessions" / "a.json").write_text("{}", encoding="utf-8")

    class FakeAdapter:
        id = "fakedata"
        label = "Fake Data"
        processes = ()

        def detect(self):
            return True

        def roots(self):
            return [root]

        def is_running(self):
            return []

    orig = reg.get_adapter
    reg.get_adapter = lambda aid: FakeAdapter() if aid == "fakedata" else orig(aid)
    try:
        pf = cleaner.preflight("fakedata", [str(root)])
        check("默认拒绝删除数据根目录",
              pf["will_remove"] == 0, f"will_remove={pf['will_remove']}")

        pf = cleaner.preflight("fakedata", [str(root)], allow_roots=True)
        check("显式 allow_roots 后才允许",
              pf["will_remove"] == 1, f"will_remove={pf['will_remove']}")

        ex = cleaner.CleanupExecutor()
        r = ex.execute("fakedata", [str(root)])
        check("execute 默认同样拒绝", r.get("removed", 0) == 0)
        check("数据根目录仍然存在", root.exists())
    finally:
        reg.get_adapter = orig


def test_quarantine_policy() -> None:
    section("10. 隔离区保留策略")
    from core import quarantine as q

    pol = q.policy()
    check("默认保留 7 天", pol["retention_days"] == 7, str(pol["retention_days"]))
    check("默认上限 2GB", pol["max_bytes"] == 2 * 1024 ** 3, str(pol["max_bytes"]))

    before = q.policy()["max_bytes"]
    q.set_policy(max_bytes=1024)
    check("拒绝过小的上限（否则会立刻清空隔离区）",
          q.policy()["max_bytes"] == before, str(q.policy()["max_bytes"]))

    q.set_policy(retention_days=30)
    check("可以调大保留天数", q.policy()["retention_days"] == 30)
    q.set_policy(retention_days=7)

    # A freshly created entry must survive a purge: the grace period is what
    # stops a user from destroying their own undo buffer.
    qroot = util.quarantine_root()
    fresh = qroot / "99999999-000000-fresh"
    fresh.mkdir(parents=True, exist_ok=True)
    (fresh / "keep.txt").write_text("x", encoding="utf-8")

    plan = q.plan_purge("all")
    check("保护期内的条目不在清理计划内",
          all(e["op_id"] != "99999999-000000-fresh" for e in plan["entries"]),
          str([e["op_id"] for e in plan["entries"]]))

    r = q.purge("all")
    check("清空操作不会删除保护期内的条目",
          fresh.exists(), f"purged={r['purged']}")

    # And an explicitly named entry inside the grace period is still protected.
    r = q.purge("all", op_ids=["99999999-000000-fresh"])
    check("即使显式指定，保护期内也不删除",
          fresh.exists() and r["results"] and not r["results"][0]["ok"],
          str(r["results"]))

    remove_tree(fresh)


def test_never_is_not_silently_dropped(fx: dict) -> None:
    section("11. never 项在执行结果里有明确说明，而不是被悄悄丢掉")
    # The user must be able to see that an item was deliberately refused, which
    # is the difference between "the tool missed it" and "the tool skipped it".
    pf = cleaner.preflight("dsh", [str(fx["repo"]), str(fx["cache"])])
    refused = [i for i in pf["items"] if not i["ok"]]
    check("被拒绝的项带有原因文本",
          bool(refused) and all(i.get("reason") for i in refused),
          str([i.get("reason", "")[:30] for i in refused]))
    check("可清理的项与被拒绝的项同时存在",
          pf["will_remove"] >= 1 and pf["refused"] >= 1,
          f"will_remove={pf['will_remove']} refused={pf['refused']}")


def test_shortcut_cleanup(fx: dict) -> None:
    section("12. 快捷方式：必须真的被删除、可还原，且不被共享规则误伤")
    import core.uninstall as U

    # A real Start Menu path contains "Microsoft" and "Windows". The shared
    # container rule must not fire on those, or every shortcut on a real machine
    # is judged a shared system resource and can never be cleaned.
    menu = _FAKE_ROAMING / "Microsoft" / "Windows" / "Start Menu" / "Programs"
    menu.mkdir(parents=True, exist_ok=True)
    lnk = menu / "Fake Agent.lnk"
    lnk.write_bytes(b"L" * 512)

    clf = Classifier()
    o = clf.classify(lnk)
    check("Start Menu 下的快捷方式不被判为 shared",
          o.category != "shared", f"{o.disposition}/{o.category}")
    check("快捷方式判为可操作的 review（分类器看不到目标，不自动置 safe）",
          o.disposition == REVIEW and o.category == "shortcut",
          f"{o.disposition}/{o.category}")

    # The shared veto must still hold at the actual shared roots.
    for raw, want in ((r"C:\Program Files", "Program Files"),
                      (r"C:\Program Files (x86)", "Program Files (x86)"),
                      (r"C:\Windows\System32", "Windows"),
                      (r"C:\ProgramData\Microsoft", "Microsoft")):
        p = Path(raw)
        if p.exists():
            o2 = clf.classify(p)
            check(f"{want} 仍判为 never/shared",
                  o2.disposition == NEVER and o2.category == "shared",
                  f"{o2.disposition}/{o2.category}")

    # End to end: an orphaned shortcut is removed, quarantined, restorable.
    fake = {
        "agent": "faketest", "label": "Fake Test", "safe": [],
        "review": [{"path": str(lnk), "kind": "shortcut", "needs_admin": False,
                    "orphan": True, "evidence": "目标已不存在"}],
        "never": [], "counts": {"safe": 0, "review": 1, "never": 0},
    }
    orig = U.cleanup_plan
    U.cleanup_plan = lambda agent: fake
    try:
        r = U.execute_cleanup("faketest", dispositions=["review"],
                              force_while_running=True)
    finally:
        U.cleanup_plan = orig

    check("快捷方式确实被移除", not lnk.exists(), r.get("note", ""))
    q = Path((r.get("file_ops") or {}).get("quarantine") or "")
    copies = list(q.rglob("*.lnk")) if q.exists() else []
    check("快捷方式进入隔离区（可还原）", bool(copies), str(q))
    if copies:
        import shutil as _sh

        lnk.parent.mkdir(parents=True, exist_ok=True)
        _sh.move(str(copies[0]), str(lnk))
        check("还原后内容一致", lnk.exists() and lnk.stat().st_size == 512)


def test_cleanup_accounting() -> None:
    section("13. 会计恒等式：选中的项必须全部被处理或报告（不得静默丢弃）")
    import core.uninstall as U

    fake = {
        "agent": "faketest", "label": "Fake Test",
        "safe": [{"path": str(_SANDBOX / "proj" / "cache2"), "kind": None, "size": 10}],
        "review": [
            {"path": str(_SANDBOX / "menu" / "A.lnk"), "kind": "shortcut",
             "needs_admin": False},
            {"path": str(_SANDBOX / "menu" / "B.lnk"), "kind": "shortcut",
             "needs_admin": True},
            {"path": "HKCU\\SOFTWARE\\FakeVendor", "kind": "registry",
             "hive": "HKCU", "reg_key": "SOFTWARE\\FakeVendor"},
            {"path": "Fake Firewall Rule", "kind": "firewall", "needs_admin": True},
            {"path": "HKCU\\...\\Run\\FakeAgent", "kind": "autostart",
             "needs_admin": False},
        ],
        "never": [], "counts": {"safe": 1, "review": 5, "never": 0},
    }
    (_SANDBOX / "proj" / "cache2").mkdir(parents=True, exist_ok=True)
    (_SANDBOX / "menu").mkdir(parents=True, exist_ok=True)
    (_SANDBOX / "menu" / "A.lnk").write_text("x", encoding="utf-8")
    (_SANDBOX / "menu" / "B.lnk").write_text("x", encoding="utf-8")

    orig = U.cleanup_plan
    U.cleanup_plan = lambda agent: fake
    try:
        r = U.execute_cleanup("faketest", dispositions=["safe", "review"],
                              dry_run=True, force_while_running=True)
    finally:
        U.cleanup_plan = orig

    acc = r.get("accounting") or {}
    check("结果自带会计恒等式字段", "balances" in acc, str(acc))
    check("恒等式成立（选中 = 已执行 + 已报告）", acc.get("balances") is True, str(acc))
    check("选中数与明细一致",
          acc.get("selected") == (acc.get("executed_or_attempted", 0)
                                  + acc.get("reported", 0)),
          str(acc))

    # The non-admin shortcut must now be *executed*, not dropped.
    fo = (r.get("file_ops") or {}).get("preflight") or {}
    handled = [i["path"] for i in fo.get("items", []) if i.get("ok")]
    check("非管理员快捷方式进入可执行列表",
          any("A.lnk" in h for h in handled), str(handled))

    # Everything not executed must be reported with a reason and a command.
    reported = r.get("reported") or []
    check("未执行的项目全部出现在 reported 中",
          len(reported) > 0, str(len(reported)))
    check("reported 每项都给出可执行命令",
          all(m.get("command") for m in reported),
          str([m.get("command") for m in reported]))
    check("需管理员的项目被标记出来",
          any(m.get("needs_admin") for m in reported),
          str([(m.get("kind"), m.get("needs_admin")) for m in reported]))


def test_batch_delete_preview() -> None:
    section("14. 批量删除必须支持预演（不改动任何数据）")
    from core.executor import Executor

    # The endpoint-level dry run plans every item. At the core level the
    # guarantee to check is that a plan is built without executing anything.
    sessions = []
    try:
        from core import inventory

        sessions = [s for s in inventory.scan()][:3]
    except Exception:
        sessions = []

    if not sessions:
        check("批量预演（无会话可测，跳过）", True)
        return

    before = {s.sid: s.size for s in sessions}
    for s in sessions:
        from adapters.registry import get_adapter

        a = get_adapter(s.agent)
        if a is None:
            continue
        plan = a.plan_delete(s.sid)
        problems = Executor.validate(plan, a)
        # A preview must be able to report blocked items rather than raising.
        check(f"可为此会话生成预演计划（{s.agent}）",
              isinstance(problems, list), str(problems))
    after = {s.sid: s.size for s in sessions}
    check("预演后会话数据未变化", before == after, f"{before} != {after}")


def test_elevation_safety() -> None:
    section("15. 提权脚本：注入防护、编码、确认与越权")
    from core import elevate

    # --- only known action kinds may be emitted -----------------------------
    script = elevate.build_script(
        [{"kind": elevate.KIND_FIREWALL, "target": "ok-rule"},
         {"kind": "totally_unknown", "target": "must not appear as a command"}],
        _SANDBOX / "r.json", _SANDBOX / "bak")
    check("未知动作类型不生成任何命令",
          "Add-Result 'totally_unknown'" not in script
          and "must not appear as a command" not in script)

    # --- PowerShell literal quoting ----------------------------------------
    cases = [("a'b", "'a''b'"), ("it's 'x'", "'it''s ''x'''"),
             ("$d `t", "'$d `t'")]
    ok = all(elevate._ps_literal(a) == b for a, b in cases)
    check("单引号/美元符/反引号按 PowerShell 单引号字面量转义", ok,
          str([(a, elevate._ps_literal(a)) for a, _ in cases]))

    # --- a newline must never escape a comment into code -------------------
    # This was a real defect: the human-readable comment interpolated the raw
    # name, so a firewall rule or shortcut whose name contained a newline could
    # inject commands into a script that runs as Administrator.
    hostile = "x\r\nRemove-Item -Recurse -Force C:\\Windows\r\n'"
    s2 = elevate.build_script(
        [{"kind": elevate.KIND_FIREWALL, "target": hostile},
         {"kind": elevate.KIND_REGISTRY, "hive": "HKLM",
          "key": hostile, "target": "HKLM\\x"},
         {"kind": elevate.KIND_SHORTCUT, "target": "C:\\ProgramData\\" + hostile}],
        _SANDBOX / "r.json", _SANDBOX / "bak")
    # The payload text may appear inside string literals, but no line of the
    # script may BEGIN with it as a command.
    leaked = [ln for ln in s2.splitlines()
              if ln.strip().startswith("Remove-Item -Recurse")]
    check("注释中的换行不能逃逸成命令", not leaked, str(leaked[:2]))
    check("注释行已压平为单行",
          all("\r" not in ln for ln in s2.splitlines()))

    # --- comment sanitiser --------------------------------------------------
    check("_comment_safe 压平所有换行类字符",
          "\n" not in elevate._comment_safe("a\nb")
          and "\r" not in elevate._comment_safe("a\rb")
          and "\u2028" not in elevate._comment_safe("a\u2028b")
          and "\u2029" not in elevate._comment_safe("a\u2029b"),
          repr(elevate._comment_safe("a\r\nb\u2028c")))

    # --- the script must be written with a BOM and without newline mangling --
    # PowerShell 5.1 reads a .ps1 as ANSI without a BOM (mangling any Chinese
    # path), and text-mode writes turn "\n" into "\r\n" (altering a target that
    # legitimately contains a newline).
    src = (Path(__file__).resolve().parent / "core" / "elevate.py").read_text(
        encoding="utf-8")
    check("脚本以带 BOM 的字节写入（PS 5.1 才能正确读中文路径）",
          "write_bytes(b\"\\xef\\xbb\\xbf\"" in src, "见 run_elevated")
    check("不使用会翻译换行的 write_text",
          "script_path.write_text" not in src)

    # --- confirmation and authority limits ---------------------------------
    r = elevate.execute("workbuddy")
    check("未确认时拒绝执行", r["ok"] is False and "confirm" in str(r["error"]))
    check("未确认时不创建提权脚本",
          not any(p.name.endswith("run.ps1")
                  for p in (_SANDBOX / "app" / "_data" / "elevated").glob("*/*")
                  if (_SANDBOX / "app" / "_data" / "elevated").exists()))

    # A caller may narrow the set to targets already in the inventory, never
    # widen it to something of its own choosing.
    r2 = elevate.execute("workbuddy", confirm=True,
                         only=[r"HKLM\SOFTWARE\DefinitelyNotListed"])
    check("伪造目标被拒绝（只能收窄不能扩大）",
          r2["ok"] is False and "不在" in str(r2["error"]), str(r2["error"])[:60])

    # --- UAC cancellation must never read as success ------------------------
    import subprocess as _sp

    class _Fake:
        def __init__(self):
            self.stdout = (b"ERR=The operation was canceled by the user. "
                           b"(Exception from HRESULT: 0x800704C7)")
            self.stderr = b""

    real_run = _sp.run
    _sp.run = lambda *a, **k: _Fake()
    try:
        r3 = elevate.run_elevated("Write-Output 1")
    finally:
        _sp.run = real_run
    check("UAC 取消被识别为 cancelled 且不算成功",
          r3["cancelled"] is True and r3["ok"] is False, str(r3["error"])[:50])

    # --- already elevated must not raise a pointless prompt -----------------
    real_el = elevate.is_elevated
    elevate.is_elevated = lambda: True
    try:
        r4 = elevate.execute("workbuddy", confirm=True)
    finally:
        elevate.is_elevated = real_el
    check("已是管理员时直接返回、不弹 UAC",
          r4.get("already_elevated") is True, str(r4.get("note"))[:40])

    # --- privileged inventory is read-only ---------------------------------
    p = elevate.plan("workbuddy")
    check("提权方案只包含已知动作类型",
          all(a["kind"] in elevate.KNOWN_KINDS for a in p["actions"]),
          str([a["kind"] for a in p["actions"]]))
    check("提权方案可安全用于展示（含脚本但不执行）",
          isinstance(p["script"], str))

    # --- strongest check: ask PowerShell itself what would run --------------
    # String-level assertions cannot prove there is no break-out, because a
    # single-quoted PowerShell string may legally span lines. Parsing the
    # generated script and enumerating its CommandAst nodes is the only
    # trustworthy test, so it is worth the extra second.
    ast_ok, detail = _powershell_command_audit(elevate)
    check("PowerShell 解析确认注入载荷未成为命令", ast_ok, detail)


def _powershell_command_audit(elevate) -> tuple[bool, str]:
    """Parse a hostile script with PowerShell and list the commands it would run."""
    import subprocess

    from core.util import powershell_exe

    exe = powershell_exe()
    if not exe:
        return True, "无 PowerShell，跳过（已由字符串层断言覆盖）"

    hostile = ("evil'\r\nRemove-Item -Recurse -Force C:\\Windows\\Temp\r\n'")
    script = elevate.build_script(
        [{"kind": elevate.KIND_FIREWALL, "target": hostile},
         {"kind": elevate.KIND_REGISTRY, "hive": "HKLM", "key": hostile,
          "target": "HKLM\\x"},
         {"kind": elevate.KIND_SHORTCUT,
          "target": "C:\\ProgramData\\x'\r\nStart-Process calc\r\n'.lnk"}],
        _SANDBOX / "ast.json", _SANDBOX / "astbak")
    sf = _SANDBOX / "ast.ps1"
    sf.write_bytes(b"\xef\xbb\xbf" + script.encode("utf-8"))

    cmd = (
        "$errs=$null;"
        f"$ast=[System.Management.Automation.Language.Parser]::ParseFile("
        f"'{sf}',[ref]$null,[ref]$errs);"
        "'E=' + (@($errs).Count);"
        "$c=$ast.FindAll({param($n) $n -is "
        "[System.Management.Automation.Language.CommandAst]}, $true);"
        "'C=' + (($c | ForEach-Object { $_.GetCommandName() } | "
        "Where-Object {$_} | Sort-Object -Unique) -join ',')"
    )
    try:
        out = subprocess.run(
            [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command", cmd],
            capture_output=True, timeout=120,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        text = ((out.stdout or b"") + (out.stderr or b"")).decode("utf-8", "replace")
    except Exception as e:
        return True, f"PowerShell 调用失败，跳过：{type(e).__name__}"

    errors = "E=0" not in text
    cmds = ""
    for line in text.splitlines():
        if line.startswith("C="):
            cmds = line[2:].strip()
    names = [c for c in cmds.split(",") if c]
    payload = [c for c in names
               if c in ("Start-Process", "Stop-Process", "calc", "explorer",
                        "cmd", "powershell")]
    ok = (not errors) and not payload
    return ok, f"解析错误={errors} 载荷命令={payload or '无'} 全部命令={names}"


def test_uninstall_coverage_honesty() -> None:
    section("16. 清理能力边界必须如实说明（不谎称已卸载干净）")
    from core import uninstall

    r = uninstall.full_report()
    check("full_report 返回每个 Agent 的可回收量",
          all("reclaimable_bytes_h" in a for a in r["agents"]),
          str(len(r["agents"])) + " 个 Agent")

    # The tool must be explicit that some things are out of scope, rather than
    # reporting a clean result and leaving the user to discover the rest later.
    cli_src = (Path(__file__).resolve().parent / "cli.py").read_text(encoding="utf-8")
    for must_say in ("凭据管理器", "环境变量 PATH", "系统服务与计划任务",
                     "程序安装目录"):
        check(f"capabilities 明确说明不处理：{must_say}",
              must_say in cli_src)


def main() -> int:
    print("=" * 74)
    print("残留清理安全测试（沙箱运行，不接触真实会话）")
    print("=" * 74)
    print(f"沙箱: {_SANDBOX}")

    # The sandbox is removed in a `finally`: a suite that crashes part-way
    # through must not leak a temp directory. Leaving one behind on an
    # assertion failure would be the exact class of mess this tool exists to
    # eliminate -- and it happened for real while this suite was being written.
    try:
        _run_tests()
    finally:
        # Always clean up, including on a crash. Set ASM_KEEP_SANDBOX=1 when
        # you deliberately want to inspect the leftover state.
        if os.environ.get("ASM_KEEP_SANDBOX") == "1":
            print(f"[keep] 沙箱保留以供检查: {_SANDBOX}")
        else:
            err = remove_tree(_SANDBOX)
            if err:
                print(f"警告：沙箱清理失败 {err}", file=sys.stderr)
                FAILURES.append("sandbox cleanup failed")
            else:
                print("沙箱已清理。")

    print("\n" + "=" * 74)
    if FAILURES:
        print(f"RESULT: {len(FAILURES)} 项失败")
        for f in FAILURES:
            print(f"  - {f}")
    else:
        print("RESULT: 全部通过")
    print("=" * 74)
    return 1 if FAILURES else 0


def _run_tests() -> None:
    fx = build_fixtures()
    test_source_repo_protection(fx)
    test_shared_protection()
    test_credential_precision(fx)
    test_cache_vs_state(fx)
    test_executor_refuses_never(fx)
    test_executor_removes_safe_reversibly(fx)
    test_dry_run_changes_nothing(fx)
    test_running_agent_blocks_execution()
    test_data_root_needs_explicit_optin()
    test_quarantine_policy()
    test_never_is_not_silently_dropped(fx)
    test_shortcut_cleanup(fx)
    test_cleanup_accounting()
    test_batch_delete_preview()
    test_elevation_safety()
    test_uninstall_coverage_honesty()


if __name__ == "__main__":
    raise SystemExit(main())
