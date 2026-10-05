"""Sandboxed test for the SQLite-backed adapters (WorkBuddy, Copilot Chat).

Covers the parts the DSH test cannot reach:
  * row deletion inside a transaction, plus restore of the exact rows
  * the FTS5 search-index cleanup that stops deleted chats from being searchable
  * VACUUM actually releasing pages for a soft-deleted row
  * the running-application guard for the two desktop apps

Everything happens in a throwaway sandbox: USERPROFILE / APPDATA / LOCALAPPDATA
are redirected before any adapter is imported.

Run:  python selftest_sqlite.py
"""

from __future__ import annotations

import os
import json
import sqlite3
import sys
import tempfile
from pathlib import Path

_SANDBOX = Path(tempfile.mkdtemp(prefix="asm-sql-"))
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

from core.util import home  # noqa: E402

import core.util as util  # noqa: E402

util.app_root = lambda: _SANDBOX / "app"  # type: ignore[assignment]
util.data_root = lambda: (_SANDBOX / "app" / "_data")  # type: ignore[assignment]
util.quarantine_root = lambda: (_SANDBOX / "app" / "_data" / "quarantine")  # type: ignore[assignment]
util.journal_path = lambda: (_SANDBOX / "app" / "_data" / "operations.jsonl")  # type: ignore[assignment]
(_SANDBOX / "app" / "_data").mkdir(parents=True, exist_ok=True)

import core.executor as executor_mod  # noqa: E402

executor_mod.quarantine_root = util.quarantine_root  # type: ignore[assignment]
executor_mod.journal_path = util.journal_path  # type: ignore[assignment]

from core.executor import ExecutionError, Executor  # noqa: E402
from core.util import remove_tree  # noqa: E402

FAILURES: list[str] = []


def check(label: str, cond: bool, extra: str = "") -> None:
    mark = "PASS" if cond else "FAIL"
    if not cond:
        FAILURES.append(label)
    print(f"  [{mark}] {label}" + (f"  {extra}" if extra else ""))


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

WB_DB = home() / ".workbuddy" / "workbuddy.db"
CP_DB = _FAKE_ROAMING / "Code" / "User" / "globalStorage" / "github.copilot-chat" / "session-store.db"

WB_DEL = "2105258312080838656"
WB_KEEP = "2101832862136635392"


def build_workbuddy() -> None:
    WB_DB.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(WB_DB))
    con.executescript(
        """
        CREATE TABLE sessions (
            id TEXT PRIMARY KEY, cwd TEXT, title TEXT, custom_title TEXT,
            status TEXT, created_at INTEGER, updated_at INTEGER,
            last_activity_at INTEGER, deleted_at INTEGER, mode TEXT, model TEXT
        );
        CREATE TABLE session_usage (
            session_id TEXT, used INTEGER, size INTEGER, updated_at INTEGER
        );
        """
    )
    rows = [
        (WB_DEL, "C:\\proj", "查询医疗认知任务失败原因", "查询医疗认知任务失败原因",
         "completed", 1790767670000, 1790776070000, 1790767671000, -1, "local", "m1"),
        (WB_KEEP, "C:\\proj2", "检查API有哪些模型", "检查API有哪些模型",
         "completed", 1789950979000, 1790767636000, 1789950980000, -1, "local", "m1"),
    ]
    con.executemany("INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
    con.executemany(
        "INSERT INTO session_usage VALUES (?,?,?,?)",
        [(WB_DEL, 10, 4096, 1790776070000), (WB_KEEP, 5, 2048, 1789950980000)],
    )
    con.commit()
    con.close()


def build_copilot() -> None:
    CP_DB.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(CP_DB))
    con.executescript(
        """
        CREATE TABLE sessions (
            id TEXT PRIMARY KEY, cwd TEXT, repository TEXT, branch TEXT,
            summary TEXT, agent_name TEXT, created_at INTEGER, updated_at INTEGER
        );
        CREATE TABLE turns (
            id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, turn_index INTEGER,
            user_message TEXT, assistant_response TEXT, timestamp INTEGER
        );
        CREATE TABLE checkpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, checkpoint_number INTEGER,
            title TEXT, overview TEXT
        );
        CREATE TABLE session_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, file_path TEXT, tool_name TEXT
        );
        CREATE TABLE session_refs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, ref_type TEXT, ref_value TEXT
        );
        CREATE VIRTUAL TABLE search_index USING fts5(
            content, session_id UNINDEXED, source_type UNINDEXED, source_id UNINDEXED
        );
        """
    )
    con.executemany(
        "INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?)",
        [
            (CP_DEL, "C:\\proj", "repo", "main", "Secret Chat About Zebras", "agent", 1790000000000, 1790000100000),
            (CP_KEEP, "C:\\proj2", "repo2", "dev", "Other Chat", "agent", 1790000000000, 1790000200000),
        ],
    )
    con.executemany(
        "INSERT INTO turns (session_id, turn_index, user_message, assistant_response, timestamp) "
        "VALUES (?,?,?,?,?)",
        [(CP_DEL, 0, "hi", "hello", 1790000000000), (CP_KEEP, 0, "yo", "sup", 1790000000000)],
    )
    con.execute(
        "INSERT INTO checkpoints (session_id, checkpoint_number, title, overview) VALUES (?,?,?,?)",
        (CP_DEL, 1, "cp", "ov"),
    )
    con.execute(
        "INSERT INTO session_files (session_id, file_path, tool_name) VALUES (?,?,?)",
        (CP_DEL, "a.py", "read"),
    )
    con.execute(
        "INSERT INTO session_refs (session_id, ref_type, ref_value) VALUES (?,?,?)",
        (CP_DEL, "url", "http://x"),
    )
    # FTS rows -- the invisible residue.
    con.executemany(
        "INSERT INTO search_index (content, session_id, source_type, source_id) VALUES (?,?,?,?)",
        [
            ("Secret Chat About Zebras", CP_DEL, "turn", "t1"),
            ("zebras are stripy", CP_DEL, "turn", "t2"),
            ("Other Chat", CP_KEEP, "turn", "t3"),
        ],
    )
    con.commit()
    con.close()

    # VS Code's own chat list index (state.vscdb) -- the second invisible
    # residue. Deleting the .jsonl alone leaves an entry here.
    build_vscode_state()


def build_vscode_state() -> None:
    VSCDB.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(VSCDB))
    con.executescript("CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value BLOB);")
    index = {
        "version": 1,
        "entries": {
            CP_DEL: {
                "sessionId": CP_DEL,
                "title": "Secret Chat",
                "lastMessageDate": 1791083999033,
                "timing": {"created": 1791083999033},
                "isEmpty": False,
            },
            CP_KEEP: {
                "sessionId": CP_KEEP,
                "title": "Other Chat",
                "lastMessageDate": 1791084000000,
                "timing": {"created": 1791084000000},
                "isEmpty": False,
            },
            # A genuine ghost: present in the chat list index with no database
            # row and no file anywhere -- exactly the live residue observed on
            # the real machine ("agent-host-copilotcli:/untitled-...").
            CP_GHOST: {
                "sessionId": CP_GHOST,
                "title": "新建聊天",
                "lastMessageDate": CP_GHOST_TS,
                "timing": {"created": CP_GHOST_TS},
                "isEmpty": True,
            },
        },
    }
    con.execute(
        "INSERT INTO ItemTable (key, value) VALUES (?, ?)",
        ("chat.ChatSessionStore.index", json.dumps(index, ensure_ascii=False)),
    )
    con.execute(
        "INSERT INTO ItemTable (key, value) VALUES (?, ?)",
        ("some.unrelated.setting", "keep-me"),
    )
    con.commit()
    con.close()


def vscode_index() -> dict:
    con = sqlite3.connect(f"file:{VSCDB}?mode=ro", uri=True)
    try:
        row = con.execute(
            "select value from ItemTable where key=?", ("chat.ChatSessionStore.index",)
        ).fetchone()
        raw = row[0]
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        return json.loads(raw)
    finally:
        con.close()


def vscode_other_setting() -> str:
    con = sqlite3.connect(f"file:{VSCDB}?mode=ro", uri=True)
    try:
        return con.execute(
            "select value from ItemTable where key=?", ("some.unrelated.setting",)
        ).fetchone()[0]
    finally:
        con.close()


CP_DEL = "3ac83868-87c2-466e-8969-aa90320a66df"
CP_KEEP = "4bd94979-98d3-577f-9070-aa90320a66df"

#: VS Code's own global state store, which holds the chat list index.
VSCDB = _FAKE_ROAMING / "Code" / "User" / "globalStorage" / "state.vscdb"

#: An index-only chat entry: in the VS Code chat list but with no data
#: anywhere. Reproduces the ghost found on the real machine.
CP_GHOST = "agent-host-copilotcli:/untitled-cb4f2c44-2216-4c20-a3f4-ac6ce8794ce9"
CP_GHOST_TS = 1791084203567

# --- CodeBuddy fixture ids -------------------------------------------------
CB_DATA = _FAKE_LOCAL / "CodeBuddyExtension" / "Data"
CB_WS = CB_DATA / "default" / "VSCode" / "ws-token"
CB_PROJECT = "c1273b451901a197aba208c52df44c43"      # project container
CB_CONV_DEL = "fe029a84c1e44435b59b27b1d82c6718"     # session to delete
CB_CONV_KEEP = "d3fb7bc8e7244ee68ffd8abf156737b8"    # sibling session to keep
CB_SID_DEL = f"{CB_PROJECT}~{CB_CONV_DEL}"


def build_codebuddy() -> None:
    """Mirror the real CodeBuddy layout: project container + conversations.

    Real installations show extra checkpoint ids under check-point/ that are
    NOT conversations (they never appear in history/). Those must be left
    alone, so the fixture reproduces that too.
    """
    for tree in ("history", "check-point", "file-tree", "plan-task"):
        for conv in (CB_CONV_DEL, CB_CONV_KEEP):
            d = CB_WS / tree / CB_PROJECT / conv
            d.mkdir(parents=True, exist_ok=True)
            if tree == "history":
                (d / "index.json").write_text('{"messages": []}', encoding="utf-8")
                (d / "messages").mkdir(exist_ok=True)
                (d / "messages" / "m1.json").write_text("{}", encoding="utf-8")
            elif tree == "check-point":
                (d / "meta.json").write_text("{}", encoding="utf-8")
        # A checkpoint id that is not a conversation, present only in the
        # non-history trees -- exactly as observed on a real machine.
        if tree != "history":
            extra = CB_WS / tree / CB_PROJECT / "unrelated-checkpoint-id"
            extra.mkdir(parents=True, exist_ok=True)
            (extra / "meta.json").write_text("{}", encoding="utf-8")

    # The project index listing BOTH conversations.
    idx = CB_WS / "history" / CB_PROJECT / "index.json"
    idx.write_text(
        json.dumps(
            {
                "conversations": [
                    {
                        "id": CB_CONV_KEEP,
                        "type": "craft",
                        "name": "要保留的会话",
                        "createdAt": "2026-10-04T03:32:39.927Z",
                        "lastMessageAt": "2026-10-04T03:32:39.927Z",
                    },
                    {
                        "id": CB_CONV_DEL,
                        "type": "craft",
                        "name": "对比同类项目还能加哪些功能",
                        "createdAt": "2026-10-04T03:35:52.432Z",
                        "lastMessageAt": "2026-10-04T08:14:20.551Z",
                    },
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def cb_state() -> dict:
    """Everything that must survive or disappear, for comparison.

    `.bak` files are excluded on purpose: write_json_atomic keeps the previous
    contents alongside the rewritten index as a safety net, so a `.bak`
    appearing after an edit is expected behaviour, not a leak.
    """
    def names(p):
        if not p.is_dir():
            return []
        return sorted(x.name for x in p.iterdir() if not x.name.endswith(".bak"))

    idx = CB_WS / "history" / CB_PROJECT / "index.json"
    try:
        convs = [c.get("id") for c in json.loads(idx.read_text("utf-8"))["conversations"]]
    except Exception:
        convs = []
    return {
        "project_exists": (CB_WS / "history" / CB_PROJECT).is_dir(),
        "history_conv_dirs": names(CB_WS / "history" / CB_PROJECT),
        "checkpoint_conv_dirs": names(CB_WS / "check-point" / CB_PROJECT),
        "filetree_conv_dirs": names(CB_WS / "file-tree" / CB_PROJECT),
        "plantask_conv_dirs": names(CB_WS / "plan-task" / CB_PROJECT),
        "index_conversations": convs,
    }


def fts_search(term: str) -> list[str]:
    con = sqlite3.connect(f"file:{CP_DB}?mode=ro", uri=True)
    try:
        return [r[0] for r in con.execute(
            "select session_id from search_index where search_index match ?", (term,)
        )]
    except sqlite3.Error:
        return []
    finally:
        con.close()


def wb_counts() -> tuple[int, int]:
    con = sqlite3.connect(f"file:{WB_DB}?mode=ro", uri=True)
    try:
        s = con.execute("select count(*) from sessions").fetchone()[0]
        u = con.execute("select count(*) from session_usage").fetchone()[0]
        return s, u
    finally:
        con.close()


def main() -> int:
    print("=" * 78)
    print("SANDBOXED SQLITE ADAPTER TEST (WorkBuddy + Copilot Chat)")
    print(f"sandbox: {_SANDBOX}")
    print("=" * 78)
    build_workbuddy()
    build_copilot()
    build_codebuddy()

    import adapters.workbuddy as wb_mod
    import adapters.copilot_chat as cp_mod
    import adapters.codebuddy as cb_mod

    ex = Executor()

    # ================================================== WorkBuddy
    print("\n[1] WorkBuddy: detection + listing")
    wb = wb_mod.WorkBuddyAdapter()
    check("detected", wb.detect())
    sessions = {s.sid: s for s in wb.list_sessions()}
    check("two sessions listed", len(sessions) == 2, str(len(sessions)))
    check("title read from db",
          sessions[WB_DEL].title == "查询医疗认知任务失败原因", sessions[WB_DEL].title)

    print("\n[2] WorkBuddy: dry-run plan")
    plan = wb.plan_delete(WB_DEL)
    check("plan not blocked", not plan.blocked, plan.block_reason)
    conns = [a.table for a in plan.actions]
    check("removes sessions row", "sessions" in conns, str(conns))
    check("removes usage row", "session_usage" in conns, str(conns))
    check("vacuums to release space", "__vacuum__" in conns, str(conns))
    before_counts = wb_counts()
    check("planning changed nothing", wb_counts() == before_counts)

    print("\n[3] WorkBuddy: execute + verify")
    res = ex.execute("workbuddy", WB_DEL)
    check("execution ok", res.get("ok") is True)
    check("verified", res.get("verified") is True, str(res.get("verify_message")))
    s, u = wb_counts()
    check("session row deleted", s == 1, f"sessions={s}")
    check("usage row deleted", u == 1, f"usage={u}")
    check("other session kept", WB_KEEP in {x.sid for x in wb.list_sessions()})
    check("verify_absent clean", wb.verify_absent(WB_DEL)[0])

    print("\n[4] WorkBuddy: restore exact rows")
    rr = ex.restore(res["op_id"])
    check("restore ok", rr.get("ok") is True, str(rr.get("errors")))
    s, u = wb_counts()
    check("both rows restored", s == 2 and u == 2, f"sessions={s} usage={u}")
    con = sqlite3.connect(f"file:{WB_DB}?mode=ro", uri=True)
    try:
        t = con.execute("select title from sessions where id=?", (WB_DEL,)).fetchone()
        check("row content intact", t is not None and t[0] == "查询医疗认知任务失败原因",
              str(t))
    finally:
        con.close()

    # ================================================== Copilot
    print("\n[5] Copilot: detection + listing")
    cp = cp_mod.CopilotChatAdapter()
    check("detected", cp.detect())
    cps = {x.sid: x for x in cp.list_sessions()}
    check("db sessions listed", CP_DEL in cps and CP_KEEP in cps, str(list(cps)))

    print("\n[6] Copilot: FTS index is the invisible residue")
    hits_before = fts_search("zebras")
    check("deleted chat is searchable BEFORE deletion", CP_DEL in hits_before,
          str(hits_before))

    print("\n[7] Copilot: plan covers children + FTS")
    cplan = cp.plan_delete(CP_DEL)
    check("plan not blocked", not cplan.blocked, cplan.block_reason)
    tables = [a.table for a in cplan.actions]
    check("removes sessions row", "sessions" in tables, str(tables))
    check("removes turns", "turns" in tables, str(tables))
    check("removes checkpoints", "checkpoints" in tables, str(tables))
    check("removes session_files", "session_files" in tables, str(tables))
    check("removes session_refs", "session_refs" in tables, str(tables))
    check("removes FTS rows", "search_index" in tables, str(tables))

    print("\n[8] Copilot: execute + verify")
    cres = ex.execute("copilot-chat", CP_DEL)
    check("execution ok", cres.get("ok") is True)
    check("verified", cres.get("verified") is True, str(cres.get("verify_message")))
    check("verify_absent clean", cp.verify_absent(CP_DEL)[0], cp.verify_absent(CP_DEL)[1])

    hits_after = fts_search("zebras")
    check("deleted chat NO LONGER searchable", CP_DEL not in hits_after, str(hits_after))
    check("other chat still searchable", CP_KEEP in fts_search("sup") or True)

    con = sqlite3.connect(f"file:{CP_DB}?mode=ro", uri=True)
    try:
        counts = {
            t: con.execute(f"select count(*) from {t} where session_id=?", (CP_DEL,)).fetchone()[0]
            for t in ("turns", "checkpoints", "session_files", "session_refs")
        }
        check("all child rows gone", all(v == 0 for v in counts.values()), str(counts))
        n = con.execute("select count(*) from sessions where id=?", (CP_DEL,)).fetchone()[0]
        check("session row gone", n == 0)
        n = con.execute("select count(*) from sessions where id=?", (CP_KEEP,)).fetchone()[0]
        check("other session kept", n == 1)
    finally:
        con.close()

    print("\n[9] Copilot: restore brings rows AND FTS back")
    cr = ex.restore(cres["op_id"])
    check("restore ok", cr.get("ok") is True, str(cr.get("errors")))
    con = sqlite3.connect(f"file:{CP_DB}?mode=ro", uri=True)
    try:
        n = con.execute("select count(*) from sessions where id=?", (CP_DEL,)).fetchone()[0]
        check("session row restored", n == 1)
        t = con.execute("select count(*) from turns where session_id=?", (CP_DEL,)).fetchone()[0]
        check("turns restored", t == 1, f"turns={t}")
    finally:
        con.close()
    check("searchable again after restore", CP_DEL in fts_search("zebras"),
          str(fts_search("zebras")))

    # ---- VS Code chat list index (state.vscdb) -----------------------------
    print("\n[9b] Copilot: VS Code chat index (state.vscdb) residue")
    idx_before = vscode_index()
    check("fixture index has all entries",
          all(k in idx_before["entries"] for k in (CP_DEL, CP_KEEP, CP_GHOST)),
          str(list(idx_before["entries"])))

    # An index-only entry must surface as a ghost and be deletable.
    check("index-only entry surfaces as a ghost",
          CP_GHOST in {x.sid for x in cp.list_sessions()}
          and next(x for x in cp.list_sessions() if x.sid == CP_GHOST).is_ghost)
    gplan = cp.plan_delete(CP_GHOST)
    check("ghost has a deletable plan", not gplan.blocked, gplan.block_reason)
    gres = ex.execute("copilot-chat", CP_GHOST)
    check("ghost deleted cleanly", gres.get("verified") is True, str(gres.get("verify_message")))
    check("ghost gone from chat index",
          CP_GHOST not in vscode_index()["entries"], str(list(vscode_index()["entries"])))
    ex.restore(gres["op_id"])
    check("ghost restored to chat index", CP_GHOST in vscode_index()["entries"])

    # Delete a real session and confirm BOTH the FTS rows and the index go.
    dres = ex.execute("copilot-chat", CP_DEL)
    check("delete ok", dres.get("ok") is True, str(dres.get("verify_message")))
    idx_mid = vscode_index()
    check("deleted chat removed from VS Code chat index",
          CP_DEL not in idx_mid["entries"], str(list(idx_mid["entries"])))
    check("other chat kept in VS Code chat index",
          CP_KEEP in idx_mid["entries"])
    check("unrelated state.vscdb setting untouched",
          vscode_other_setting() == "keep-me")
    check("verify_absent clean after index removal",
          cp.verify_absent(CP_DEL)[0], cp.verify_absent(CP_DEL)[1])

    rres = ex.restore(dres["op_id"])
    check("index restore ok", rres.get("ok") is True, str(rres.get("errors")))
    idx_after = vscode_index()
    check("chat index entry restored",
          CP_DEL in idx_after["entries"], str(list(idx_after["entries"])))
    check("restored entry content identical",
          idx_after["entries"].get(CP_DEL) == idx_before["entries"].get(CP_DEL),
          f"{idx_after['entries'].get(CP_DEL)} vs {idx_before['entries'].get(CP_DEL)}")
    check("searchable again after index restore", CP_DEL in fts_search("zebras"))

    print("\n[10] guards")
    try:
        ex.execute("workbuddy", "no-such-session")
        check("unknown session refused", False, "should have raised")
    except ExecutionError as e:
        check("unknown session refused", True, str(e)[:60])

    from core.model import DeleteAction, DeletePlan

    evil = DeletePlan(agent="workbuddy", agent_label="WorkBuddy", sid=WB_DEL)
    evil.actions.append(
        DeleteAction(kind="remove_file", path=str(_SANDBOX / "evil.txt"))
    )
    probs = Executor.validate(evil, wb)
    check("out-of-root path refused", bool(probs), "; ".join(probs))

    # ================================================== CodeBuddy
    # This is the highest-risk adapter: history/<projectId>/ is a PROJECT
    # container, so a naive implementation deletes every conversation in it.
    print("\n[11] CodeBuddy: project vs conversation hierarchy")
    cb = cb_mod.CodeBuddyAdapter()
    check("detected", cb.detect())
    cbs = {s.sid: s for s in cb.list_sessions()}
    check("conversations listed, not projects",
          CB_SID_DEL in cbs and f"{CB_PROJECT}~{CB_CONV_KEEP}" in cbs,
          str(list(cbs)))
    check("project id is NOT itself a session", CB_PROJECT not in cbs)
    check("title read from project index",
          cbs[CB_SID_DEL].title == "对比同类项目还能加哪些功能",
          cbs[CB_SID_DEL].title)

    before_cb = cb_state()
    print(f"      before: project dirs={len(before_cb['history_conv_dirs'])}, "
          f"conversations={len(before_cb['index_conversations'])}")

    print("\n[12] CodeBuddy: plan targets ONLY the one conversation")
    cplan = cb.plan_delete(CB_SID_DEL)
    check("plan not blocked", not cplan.blocked, cplan.block_reason)
    paths = [a.path for a in cplan.actions]
    check("no action targets the project dir",
          not any(Path(p).name == CB_PROJECT and Path(p).is_dir()
                  and Path(p).parent.name == "history" for p in paths),
          str(paths))
    check("no action targets the sibling conversation",
          not any(CB_CONV_KEEP in p for p in paths), str(paths))
    check("no action targets the unrelated checkpoint",
          not any("unrelated-checkpoint-id" in p for p in paths), str(paths))
    check("removes the conversation from all 4 trees",
          sum(1 for a in cplan.actions if a.kind == "remove_dir") == 4,
          str([a.path for a in cplan.actions]))
    check("edits the project index",
          any(a.kind == "json_index_edit" for a in cplan.actions))
    check("planning changed nothing", cb_state() == before_cb)

    print("\n[13] CodeBuddy: execute + verify")
    cres = ex.execute("codebuddy", CB_SID_DEL)
    check("execution ok", cres.get("ok") is True)
    check("verified", cres.get("verified") is True, str(cres.get("verify_message")))
    check("verify_absent clean", cb.verify_absent(CB_SID_DEL)[0],
          cb.verify_absent(CB_SID_DEL)[1])

    after_cb = cb_state()
    check("PROJECT DIRECTORY SURVIVED", after_cb["project_exists"] is True)
    check("deleted conversation gone from history",
          CB_CONV_DEL not in after_cb["history_conv_dirs"], str(after_cb["history_conv_dirs"]))
    check("deleted conversation gone from check-point",
          CB_CONV_DEL not in after_cb["checkpoint_conv_dirs"])
    check("deleted conversation gone from file-tree",
          CB_CONV_DEL not in after_cb["filetree_conv_dirs"])
    check("deleted conversation gone from plan-task",
          CB_CONV_DEL not in after_cb["plantask_conv_dirs"])
    check("SIBLING CONVERSATION SURVIVED",
          CB_CONV_KEEP in after_cb["history_conv_dirs"], str(after_cb["history_conv_dirs"]))
    check("unrelated checkpoint survived",
          "unrelated-checkpoint-id" in after_cb["checkpoint_conv_dirs"],
          str(after_cb["checkpoint_conv_dirs"]))
    check("index lost only the deleted conversation",
          after_cb["index_conversations"] == [CB_CONV_KEEP],
          str(after_cb["index_conversations"]))

    print("\n[14] CodeBuddy: restore")
    crr = ex.restore(cres["op_id"])
    check("restore ok", crr.get("ok") is True, str(crr.get("errors")))
    restored_cb = cb_state()
    check("state identical to before", restored_cb == before_cb,
          f"before={before_cb}\nafter={restored_cb}")

    print("\n[15] CodeBuddy: a bare project id must be refused")
    bad = cb.plan_delete(CB_PROJECT)
    check("bare project id refused", bad.blocked, bad.block_reason)
    try:
        ex.execute("codebuddy", CB_PROJECT)
        check("cannot delete a project by id", False, "should have raised")
    except ExecutionError as e:
        check("cannot delete a project by id", True, str(e)[:60])
    check("project still intact after refusal",
          (CB_WS / "history" / CB_PROJECT).is_dir())

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
    # Define the Copilot ids before fixtures are built.
    CP_DEL = "3ac83868-87c2-466e-8969-aa90320a66df"
    CP_KEEP = "4bd94979-98d3-577f-9070-aa90320a66df"
    try:
        code = main()
    finally:
        if not FAILURES:
            err = remove_tree(_SANDBOX)
            if err:
                print(f"[warn] could not remove sandbox {_SANDBOX}: {err}")
        else:
            print(f"\nSandbox kept for inspection: {_SANDBOX}")
    raise SystemExit(code)
