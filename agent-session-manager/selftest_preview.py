"""Tests for the read-only conversation preview.

Two things must hold:

  1. preview() never modifies anything -- verified by fingerprinting every byte
     of the relevant stores before and after previewing every session.
  2. preview() never raises, and always explains itself when it has nothing to
     show (a ghost, a cloud-only session, an empty chat).

Also seeds synthetic fixtures for the formats that the real machine does not
exercise (a DSH transcript with every message kind, a Copilot chat with turns
and an FTS index) so the parsing itself is covered.

Run:  python selftest_preview.py
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

_SANDBOX = Path(tempfile.mkdtemp(prefix="asm-pv-"))
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

FAILURES: list[str] = []


def check(label: str, cond: bool, extra: str = "") -> None:
    if not cond:
        FAILURES.append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}" + (f"  {extra}" if extra else ""))


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

SID_FULL = "session-aaaa1111-1111-1111-1111-111111111111"
SID_EMPTY = "session-bbbb2222-2222-2222-2222-222222222222"
SID_GHOST = "session-cccc3333-3333-3333-3333-333333333333"
DSH_WS = home() / ".dsh" / "sessions" / "--C-Users-test-proj--"

CP_DB = _FAKE_ROAMING / "Code" / "User" / "globalStorage" / "github.copilot-chat" / "session-store.db"
CP_SID = "11112222-3333-4444-5555-666677778888"


def build_dsh() -> None:
    from compression import zstd

    cache = home() / ".dsh" / "storages" / "session_projcache" / "sessions"
    cache.mkdir(parents=True, exist_ok=True)

    events = [
        {"type": "session", "version": 4, "id": SID_FULL,
         "createdAt": 1790000000000, "cwd": "C:\\Users\\test\\proj"},
        {"type": "user/message", "seq": 1, "time": 1790000001000,
         "data": {"content": [
             {"type": "text", "text": "请帮我看看这个目录结构"},
             {"type": "image", "attachment": {"name": "shot.png", "width": 800,
                                              "height": 600, "bytes": 12345}},
         ]}},
        {"type": "assistant/message", "seq": 2, "time": 1790000002000,
         "data": {"message": {"role": "assistant", "content": [
             {"type": "reasoning", "text": "先列目录再读关键文件。"},
             {"type": "text", "text": "我先看一下目录结构。"},
         ]}}},
        {"type": "tool/call", "seq": 3, "time": 1790000003000,
         "data": {"name": "list_dir", "arguments": '{"path":"."}'}},
        {"type": "tool/result", "seq": 4, "time": 1790000004000,
         "data": {"message": {"role": "tool", "isError": False, "content": [
             {"type": "text", "text": "src/\ntests/\nREADME.md"}]}}},
        {"type": "tool/result", "seq": 5, "time": 1790000005000,
         "data": {"message": {"role": "tool", "isError": True, "content": [
             {"type": "text", "text": "Error: permission denied"}]}}},
        {"type": "step/start", "seq": 6, "time": 1790000006000, "data": {}},
    ]

    d = DSH_WS / SID_FULL
    d.mkdir(parents=True, exist_ok=True)
    (d / "session.v4.jsonl.zstd").write_bytes(
        zstd.compress("\n".join(json.dumps(e, ensure_ascii=False) for e in events).encode())
    )
    (cache / f"{SID_FULL}.json").write_text(json.dumps({
        "version": 7,
        "record": {
            "identity": {"formatVersion": 4, "createdAt": 1790000000000,
                         "cwd": "C:\\Users\\test\\proj"},
            "rows": {"title": {"ver": 1, "seq": 1, "val": "目录结构排查"}},
        },
    }, ensure_ascii=False), encoding="utf-8")

    # An empty-but-present session (header only).
    d2 = DSH_WS / SID_EMPTY
    d2.mkdir(parents=True, exist_ok=True)
    (d2 / "session.v4.jsonl.zstd").write_bytes(zstd.compress(
        json.dumps({"type": "session", "version": 4, "id": SID_EMPTY,
                    "createdAt": 1790000000000, "cwd": "C:\\Users\\test\\empty"}).encode()
    ))
    (cache / f"{SID_EMPTY}.json").write_text(json.dumps({
        "version": 7,
        "record": {"identity": {"formatVersion": 4},
                   "rows": {"title": {"ver": 1, "seq": 1, "val": "空会话"}}},
    }, ensure_ascii=False), encoding="utf-8")

    # A ghost: metadata only.
    (cache / f"{SID_GHOST}.json").write_text(json.dumps({
        "version": 7,
        "record": {"identity": {"formatVersion": 4, "cwd": "C:\\Users\\test\\ghost"},
                   "rows": {"title": {"ver": 1, "seq": 1, "val": "幽灵"}}},
    }, ensure_ascii=False), encoding="utf-8")

    # Workspace index referencing them, so nothing looks like an orphan.
    ws = home() / ".dsh" / "storages" / "workspace.json"
    ws.parent.mkdir(parents=True, exist_ok=True)
    ws.write_text(json.dumps({
        "unit": {"name": "workspace", "version": 2},
        "global": {"workspaceIds": ["w1"], "archivedSessionIds": [], "pinnedSessionIds": []},
        "tables": {"workspaces": {"w1": {
            "path": "C:\\Users\\test\\proj", "title": "proj",
            "sessionIds": [SID_FULL, SID_EMPTY]}}},
    }), encoding="utf-8")


def build_copilot() -> None:
    CP_DB.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(CP_DB))
    con.executescript("""
        CREATE TABLE sessions (id TEXT PRIMARY KEY, cwd TEXT, repository TEXT,
            branch TEXT, summary TEXT, agent_name TEXT, created_at INTEGER,
            updated_at INTEGER);
        CREATE TABLE turns (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT,
            turn_index INTEGER, user_message TEXT, assistant_response TEXT,
            timestamp INTEGER);
        CREATE VIRTUAL TABLE search_index USING fts5(
            content, session_id UNINDEXED, source_type UNINDEXED, source_id UNINDEXED);
    """)
    con.execute("INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?)",
                (CP_SID, "C:\\p", "r", "main", "Copilot 会话", "agent",
                 1790000000000, 1790000100000))
    con.executemany(
        "INSERT INTO turns (session_id, turn_index, user_message, assistant_response,"
        " timestamp) VALUES (?,?,?,?,?)",
        [(CP_SID, 0, "第一个问题", "第一个回答", 1790000001000),
         (CP_SID, 1, "第二个问题", "第二个回答", 1790000200000)],
    )
    con.execute("INSERT INTO search_index VALUES (?,?,?,?)",
                ("第一个问题 第一个回答", CP_SID, "turn", "t1"))
    con.commit()
    con.close()


def fingerprint() -> str:
    """Hash every file that preview is allowed to read."""
    h = hashlib.sha256()
    roots = [home() / ".dsh", _FAKE_ROAMING / "Code"]
    for root in roots:
        if not root.exists():
            continue
        for p in sorted(root.rglob("*")):
            if p.is_file():
                h.update(str(p.relative_to(root)).encode("utf-8", "replace"))
                try:
                    h.update(p.read_bytes())
                except OSError:
                    h.update(b"<unreadable>")
    return h.hexdigest()


# --------------------------------------------------------------------------


def main() -> int:
    print("=" * 76)
    print("PREVIEW TEST (read-only)")
    print(f"sandbox: {_SANDBOX}")
    print("=" * 76)
    build_dsh()
    build_copilot()

    from adapters.registry import all_adapters, get_adapter

    before = fingerprint()
    total_previews = 0
    problems: list[str] = []

    print("\n[1] preview every session of every adapter, and prove nothing changed")
    for a in all_adapters():
        if not a.detect():
            continue
        sessions = a.list_sessions()
        print(f"  {a.label}: {len(sessions)} session(s)")
        for s in sessions:
            total_previews += 1
            try:
                p = a.preview(s.sid)
            except Exception as e:
                problems.append(f"{a.id}/{s.sid}: raised {type(e).__name__}: {e}")
                continue
            # Shape contract.
            for key in ("agent", "sid", "title", "available", "reason",
                        "messages", "truncated", "total_messages"):
                if key not in p:
                    problems.append(f"{a.id}/{s.sid}: missing key {key!r}")
            if p.get("sid") != s.sid:
                problems.append(f"{a.id}/{s.sid}: sid mismatch {p.get('sid')!r}")
            if not p.get("available") and not p.get("reason"):
                problems.append(f"{a.id}/{s.sid}: unavailable with no reason")
            if p.get("available") and not p.get("messages") and not p.get("reason"):
                problems.append(f"{a.id}/{s.sid}: available but empty and unexplained")

    check("no adapter preview raised or broke the contract", not problems,
          "; ".join(problems[:3]))
    check(f"previewed {total_previews} session(s)", total_previews > 0)
    after = fingerprint()
    check("PREVIEW MODIFIED NOTHING (byte-identical stores)", before == after)

    print("\n[2] DSH: every message kind is parsed")
    dsh = get_adapter("dsh")
    p = dsh.preview(SID_FULL)
    check("available", p["available"] is True)
    check("title from metadata", p["title"] == "目录结构排查", p["title"])
    kinds = [m["kind"] for m in p["messages"]]
    roles = [m["role"] for m in p["messages"]]
    check("user text parsed", "text" in kinds and "user" in roles)
    check("image parsed", "image" in kinds, str(kinds))
    check("reasoning parsed", "reasoning" in kinds, str(kinds))
    check("tool-call parsed", "tool-call" in kinds, str(kinds))
    check("tool-result parsed", "tool-result" in kinds, str(kinds))
    check("tool name captured",
          any(m["tool"] == "list_dir" for m in p["messages"]),
          str([m["tool"] for m in p["messages"]]))
    check("tool error flagged",
          any(m["is_error"] for m in p["messages"]),
          str([(m["tool"], m["is_error"]) for m in p["messages"]]))
    check("bookkeeping events excluded (no step/start)",
          all("step" not in (m.get("kind") or "") for m in p["messages"]))
    check("timestamps present", all(m["time"] for m in p["messages"]))
    check("cwd reported", p["extra"].get("cwd") == "C:\\Users\\test\\proj",
          str(p["extra"].get("cwd")))

    print("\n[3] DSH: empty session and ghost are explained, not silently blank")
    e = dsh.preview(SID_EMPTY)
    check("empty session explained",
          e["available"] is True and not e["messages"] and bool(e["reason"]),
          e["reason"][:70])
    g = dsh.preview(SID_GHOST)
    check("ghost explained as having no body",
          "幽灵" in g["reason"] or "正文" in g["reason"], g["reason"][:70])
    check("ghost reports has_content False",
          g["extra"].get("has_content") is False)

    print("\n[4] DSH: hostile ids are refused without raising")
    for bad in ("../../etc/passwd", "a/b", "", "x" * 300):
        try:
            r = dsh.preview(bad)
            check(f"refused {bad!r} gracefully", r["available"] is False and bool(r["reason"]))
        except Exception as ex:
            check(f"refused {bad!r} gracefully", False, f"raised {type(ex).__name__}")

    print("\n[5] Copilot: database turns are rendered")
    cp = get_adapter("copilot-chat")
    c = cp.preview(CP_SID)
    check("available", c["available"] is True, c.get("reason", "")[:60])
    check("both turns rendered", len(c["messages"]) == 4, str(len(c["messages"])))
    check("user then assistant order preserved",
          [m["role"] for m in c["messages"]] == ["user", "assistant", "user", "assistant"],
          str([m["role"] for m in c["messages"]]))
    check("turn text intact",
          c["messages"][0]["text"] == "第一个问题", c["messages"][0]["text"])
    check("source reported", any("turns" in s for s in c["extra"]["sources"]),
          str(c["extra"]["sources"]))

    print("\n[6] preview is idempotent and does not leak state")
    a1 = json.dumps(dsh.preview(SID_FULL), sort_keys=True, default=str)
    a2 = json.dumps(dsh.preview(SID_FULL), sort_keys=True, default=str)
    check("two previews are identical", a1 == a2)

    final = fingerprint()
    check("still byte-identical after all previews", before == final)

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
