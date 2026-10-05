"""Local web server for the Agent Session Manager.

Standard library only (http.server + json). Binds to 127.0.0.1 exclusively and
performs no network I/O of any kind beyond serving its own UI.

Start:  python server.py [--port 8799] [--no-browser]
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core import export as export_mod  # noqa: E402
from core import (  # noqa: E402
    dupes,
    history,
    inventory,
    projects,
    quarantine,
    residue,
    retention,
    search,
    secrets,
    store,
    uninstall,
    usage,
)
from core.cleaner import CleanupError  # noqa: E402
from core.executor import ExecutionError, Executor  # noqa: E402
from core.util import plat  # noqa: E402

WEB_DIR = Path(__file__).resolve().parent / "web"
HOST = "127.0.0.1"


class Handler(BaseHTTPRequestHandler):
    server_version = "AgentSessionManager/1.0"

    # ------------------------------------------------------------------ output

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        # The UI is local-only; deny framing and sniffing outright.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionAbortedError):
            pass

    def json_out(self, obj, code: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
        self._send(code, body, "application/json; charset=utf-8")

    def error_out(self, msg: str, code: int = 400, detail: str = "") -> None:
        self.json_out({"ok": False, "error": msg, "detail": detail}, code)

    def log_message(self, fmt, *args) -> None:  # quieter console
        return

    # -------------------------------------------------------------------- GET

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]

        if path in ("/", "/index.html"):
            return self._serve_file(WEB_DIR / "index.html", "text/html; charset=utf-8")
        if path.startswith("/static/"):
            rel = path[len("/static/"):]
            target = (WEB_DIR / rel).resolve()
            if not str(target).startswith(str(WEB_DIR.resolve())):
                return self.error_out("路径越界", 403)
            ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
            return self._serve_file(target, ctype)

        if path == "/api/report":
            try:
                return self.json_out({"ok": True, **inventory.report(force=True)})
            except Exception as e:
                return self.error_out("扫描失败", 500, f"{type(e).__name__}: {e}")

        if path == "/api/sessions":
            try:
                sessions = inventory.scan(force=True)
                payload = [s.to_dict() for s in sessions]
                # Pins / tags / notes live in the tool's own store.
                store.decorate(payload)
                return self.json_out(
                    {
                        "ok": True,
                        "count": len(payload),
                        "sessions": payload,
                        "state": store.counts(),
                    }
                )
            except Exception as e:
                return self.error_out("读取会话失败", 500, f"{type(e).__name__}: {e}")

        # /api/search?q=...&agent=...&regex=1&case=1
        if path == "/api/search":
            q = self._query()
            try:
                r = search.search(
                    q.get("q", ""),
                    agent=q.get("agent", ""),
                    case_sensitive=q.get("case") in ("1", "true"),
                    regex=q.get("regex") in ("1", "true"),
                )
                store.decorate(r["results"])
                return self.json_out({"ok": True, **r})
            except Exception as e:
                return self.error_out("搜索失败", 500, f"{type(e).__name__}: {e}")

        if path == "/api/search-stats":
            try:
                return self.json_out({"ok": True, **search.stats()})
            except Exception as e:
                return self.error_out("读取索引状态失败", 500, str(e))

        if path == "/api/workspace-pins":
            try:
                return self.json_out(
                    {"ok": True, "workspace_pins": store.workspace_pins(),
                     **store.counts()}
                )
            except Exception as e:
                return self.error_out("读取工作区保留失败", 500, str(e))

        if path == "/api/usage":
            try:
                return self.json_out({"ok": True, **usage.summary()})
            except Exception as e:
                return self.error_out("读取用量失败", 500, f"{type(e).__name__}: {e}")

        # /api/retention?days=30&rules=ghost,orphan,old&max_kb=20&min_mb=5
        if path == "/api/retention":
            q = self._query()
            try:
                sessions = [s.to_dict() for s in inventory.scan()]
                store.decorate(sessions)
                rules = [r for r in (q.get("rules") or "").split(",") if r]
                needs_preview = "blank" in (rules or retention.RULES)
                previews = {}
                if needs_preview:
                    from adapters.registry import get_adapter

                    for s in sessions:
                        a = get_adapter(s["agent"])
                        if a is None:
                            continue
                        try:
                            previews[f"{s['agent']}|{s['sid']}"] = a.preview(s["sid"])
                        except Exception:
                            continue
                r = retention.evaluate(
                    sessions,
                    previews=previews,
                    rules=rules or None,
                    days=int(q.get("days") or 30),
                    max_kb=int(q.get("max_kb") or 20),
                    min_mb=int(q.get("min_mb") or 5),
                )
                return self.json_out({"ok": True, **r})
            except Exception as e:
                return self.error_out("计算清理建议失败", 500, f"{type(e).__name__}: {e}")

        if path == "/api/exports":
            try:
                return self.json_out({"ok": True, "exports": export_mod.list_exports()})
            except Exception as e:
                return self.error_out("读取导出记录失败", 500, str(e))

        # /api/scores   -- value tiers, to make bulk decisions less blind
        if path == "/api/scores":
            try:
                sessions = [s.to_dict() for s in inventory.scan()]
                store.decorate(sessions)
                usage_by = {}
                for s in sessions:
                    try:
                        usage_by[f"{s['agent']}|{s['sid']}"] = usage.for_session(
                            s["agent"], s["sid"]
                        )
                    except Exception:
                        continue
                previews = {}
                from adapters.registry import get_adapter

                for s in sessions:
                    a = get_adapter(s["agent"])
                    if a is None:
                        continue
                    try:
                        previews[f"{s['agent']}|{s['sid']}"] = a.preview(s["sid"])
                    except Exception:
                        continue
                scores = retention.score_all(sessions, usage_by, previews)
                out = []
                for s in sessions:
                    key = f"{s['agent']}|{s['sid']}"
                    q = scores.get(key) or {}
                    out.append({**s, "score": q})
                out.sort(key=lambda x: (x["score"] or {}).get("score", 0))
                return self.json_out(
                    {
                        "ok": True,
                        "sessions": out,
                        "signals": retention.SCORE_SIGNALS,
                        "tiers": [
                            {"key": k, "label": lbl, "why": why}
                            for _f, k, lbl, why in retention.TIERS
                        ],
                        "note": "评分为建议值，不是删除依据；标记为「无法评估」的会话请勿仅凭分数删除。",
                    }
                )
            except Exception as e:
                return self.error_out("计算评分失败", 500, f"{type(e).__name__}: {e}")

        if path == "/api/health":
            try:
                findings = inventory.health(force=True)
                return self.json_out({"ok": True, "findings": findings})
            except Exception as e:
                return self.error_out("检查失败", 500, str(e))

        if path == "/api/reclaimable":
            try:
                return self.json_out({"ok": True, "items": inventory.reclaimable()})
            except Exception as e:
                return self.error_out("读取失败", 500, str(e))

        # ---- disk ownership & residue --------------------------------------
        # /api/ownership?depth=3   -- what belongs to whom, and how sure we are
        if path == "/api/ownership":
            q = self._query()
            try:
                from core.ownership import scan_all

                depth = max(1, min(6, int(q.get("depth") or 3)))
                return self.json_out({"ok": True, **scan_all(max_depth=depth)})
            except Exception as e:
                return self.error_out("归属分析失败", 500, f"{type(e).__name__}: {e}")

        # /api/residue?agent=dsh   -- leftovers, with per-item evidence
        if path == "/api/residue":
            q = self._query()
            agent = q.get("agent", "")
            try:
                if agent:
                    return self.json_out({"ok": True, **residue.scan_agent(agent)})
                return self.json_out({"ok": True, **residue.scan_all_agents()})
            except Exception as e:
                return self.error_out("残留扫描失败", 500, f"{type(e).__name__}: {e}")

        # /api/uninstall/preflight?agent=dsh
        if path == "/api/uninstall/preflight":
            q = self._query()
            agent = q.get("agent", "")
            if not agent:
                return self.error_out("缺少 agent 参数")
            try:
                return self.json_out({"ok": True, **uninstall.preflight(agent)})
            except Exception as e:
                return self.error_out("卸载预检失败", 500, f"{type(e).__name__}: {e}")

        # /api/uninstall/plan?agent=dsh
        if path == "/api/uninstall/plan":
            q = self._query()
            agent = q.get("agent", "")
            if not agent:
                return self.error_out("缺少 agent 参数")
            try:
                return self.json_out({"ok": True, **uninstall.cleanup_plan(agent)})
            except Exception as e:
                return self.error_out("生成清理方案失败", 500, f"{type(e).__name__}: {e}")

        # /api/uninstall/verify?agent=dsh
        if path == "/api/uninstall/verify":
            q = self._query()
            agent = q.get("agent", "")
            if not agent:
                return self.error_out("缺少 agent 参数")
            try:
                return self.json_out({"ok": True, **uninstall.verify(agent)})
            except Exception as e:
                return self.error_out("卸载后验证失败", 500, f"{type(e).__name__}: {e}")

        # /api/uninstall/report?agent=dsh
        if path == "/api/uninstall/report":
            q = self._query()
            agent = q.get("agent", "")
            if not agent:
                return self.error_out("缺少 agent 参数")
            try:
                return self.json_out({"ok": True, **uninstall.report(agent)})
            except Exception as e:
                return self.error_out("生成报告失败", 500, f"{type(e).__name__}: {e}")

        # /api/uninstall/overview   -- every agent, for the overview page
        if path == "/api/uninstall/overview":
            try:
                return self.json_out({"ok": True, **uninstall.full_report()})
            except Exception as e:
                return self.error_out("读取卸载概览失败", 500, f"{type(e).__name__}: {e}")

        # ---- quarantine policy ---------------------------------------------
        if path == "/api/quarantine":
            try:
                return self.json_out({"ok": True, **quarantine.stats()})
            except Exception as e:
                return self.error_out("读取隔离区失败", 500, str(e))

        # /api/quarantine/plan?mode=expired|over_cap|all
        if path == "/api/quarantine/plan":
            q = self._query()
            try:
                return self.json_out(
                    {"ok": True, **quarantine.plan_purge(q.get("mode") or "expired")}
                )
            except Exception as e:
                return self.error_out("计算清理方案失败", 500, str(e))

        if path == "/api/cleanup-operations":
            try:
                from core.cleaner import list_cleanup_operations

                return self.json_out(
                    {"ok": True, "operations": list_cleanup_operations()}
                )
            except Exception as e:
                return self.error_out("读取清理记录失败", 500, str(e))

        # ---- history / trend ------------------------------------------------
        # /api/history?agent=dsh&days=90
        if path == "/api/history":
            q = self._query()
            try:
                return self.json_out(
                    {
                        "ok": True,
                        "summary": history.summarize(),
                        "series": history.series(
                            q.get("agent", ""), days=int(q.get("days") or 90)
                        ),
                        "trend": history.trend(
                            q.get("agent", ""), days=int(q.get("days") or 30)
                        ),
                    }
                )
            except Exception as e:
                return self.error_out("读取增长趋势失败", 500, f"{type(e).__name__}: {e}")

        # ---- projects --------------------------------------------------------
        if path == "/api/projects":
            try:
                sessions = [s.to_dict() for s in inventory.scan()]
                store.decorate(sessions)
                scores = {}
                usage_by = {}
                for s in sessions:
                    try:
                        usage_by[f"{s['agent']}|{s['sid']}"] = usage.for_session(
                            s["agent"], s["sid"]
                        )
                    except Exception:
                        continue
                try:
                    from adapters.registry import get_adapter

                    previews = {}
                    for s in sessions:
                        a = get_adapter(s["agent"])
                        if a is None:
                            continue
                        try:
                            previews[f"{s['agent']}|{s['sid']}"] = a.preview(s["sid"])
                        except Exception:
                            continue
                    scores = retention.score_all(sessions, usage_by, previews)
                except Exception:
                    scores = {}
                return self.json_out(
                    {"ok": True, **projects.group(sessions, scores, usage_by)}
                )
            except Exception as e:
                return self.error_out("项目聚合失败", 500, f"{type(e).__name__}: {e}")

        # ---- duplicates ------------------------------------------------------
        # /api/dupes?min_kb=4
        if path == "/api/dupes":
            q = self._query()
            try:
                min_bytes = max(1024, int(q.get("min_kb") or 4) * 1024)
                return self.json_out({"ok": True, **dupes.find(min_bytes=min_bytes)})
            except Exception as e:
                return self.error_out("重复内容检测失败", 500, f"{type(e).__name__}: {e}")

        # ---- secrets ---------------------------------------------------------
        # /api/secrets?agent=dsh&sid=...   (one session)
        if path == "/api/secrets":
            q = self._query()
            agent, sid = q.get("agent", ""), q.get("sid", "")
            try:
                if agent and sid:
                    return self.json_out(
                        {"ok": True, **secrets.scan_session(agent, sid)}
                    )
                sessions = [s.to_dict() for s in inventory.scan()]
                return self.json_out({"ok": True, **secrets.scan_sessions(sessions)})
            except Exception as e:
                return self.error_out("敏感信息扫描失败", 500, f"{type(e).__name__}: {e}")

        if path == "/api/secrets/patterns":
            return self.json_out(
                {
                    "ok": True,
                    "patterns": [
                        {"id": p["id"], "label": p["label"], "severity": p["severity"]}
                        for p in secrets.PATTERNS
                    ],
                }
            )

        if path == "/api/operations":
            try:
                return self.json_out({"ok": True, "operations": Executor.list_operations()})
            except Exception as e:
                return self.error_out("读取操作记录失败", 500, str(e))

        # /api/plan?agent=dsh&sid=...
        if path == "/api/plan":
            q = self._query()
            agent, sid = q.get("agent", ""), q.get("sid", "")
            if not agent or not sid:
                return self.error_out("缺少 agent 或 sid 参数")
            from adapters.registry import get_adapter

            adapter = get_adapter(agent)
            if adapter is None:
                return self.error_out(f"未知的 Agent：{agent}", 404)
            try:
                plan = adapter.plan_delete(sid)
                problems = Executor.validate(plan, adapter)
                payload = plan.to_dict()
                payload["validation_problems"] = problems
                payload["can_execute"] = (not plan.blocked) and not problems
                # Let the client echo this back so a stale confirmation can be
                # detected at execution time.
                from core.executor import plan_fingerprint

                payload["fingerprint"] = plan_fingerprint(plan)
                # Protection state, so the dialog can explain a refusal up front.
                s = inventory.find(agent, sid)
                cwd = (s.cwd if s else "") or ""
                payload["pinned"] = store.is_pinned(agent, sid)
                ws = store.match_workspace(agent, cwd) if cwd else None
                payload["workspace_protected"] = ws is not None
                payload["workspace_pin_path"] = (ws or {}).get("path", "")
                payload["workspace_pin_reason"] = (ws or {}).get("reason", "")
                payload["protected"] = bool(payload["pinned"] or payload["workspace_protected"])
                return self.json_out({"ok": True, "plan": payload})
            except Exception as e:
                return self.error_out("生成计划失败", 500, f"{type(e).__name__}: {e}")

        # /api/preview?agent=dsh&sid=...   (strictly read-only)
        if path == "/api/preview":
            q = self._query()
            agent, sid = q.get("agent", ""), q.get("sid", "")
            if not agent or not sid:
                return self.error_out("缺少 agent 或 sid 参数")
            from adapters.registry import get_adapter

            adapter = get_adapter(agent)
            if adapter is None:
                return self.error_out(f"未知的 Agent：{agent}", 404)
            session = inventory.find(agent, sid)
            try:
                data = adapter.preview(sid)
            except Exception as e:
                return self.error_out(
                    "读取会话内容失败", 500, f"{type(e).__name__}: {e}"
                )
            if session is not None:
                data.setdefault("session", session.to_dict())
                # Prefer the adapter's own title only when it has one.
                if not data.get("title"):
                    data["title"] = session.title
            return self.json_out({"ok": True, **data})

        return self.error_out("未知的接口", 404)

    # ------------------------------------------------------------------- POST

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}") if length else {}
        except (ValueError, OSError):
            return self.error_out("请求体不是合法 JSON")

        if path == "/api/delete":
            agent = body.get("agent", "")
            sid = body.get("sid", "")
            if not agent or not sid:
                return self.error_out("缺少 agent 或 sid")
            ex = Executor()
            try:
                result = ex.execute(
                    agent,
                    sid,
                    allow_permanent=bool(body.get("permanent")),
                    include_attachments=bool(body.get("include_attachments")),
                    allow_unpin=bool(body.get("allow_unpin")),
                    expected_fingerprint=str(body.get("fingerprint") or ""),
                )
                return self.json_out({"ok": True, **result})
            except ExecutionError as e:
                return self.error_out("删除失败", 409, str(e))
            except Exception as e:
                return self.error_out("删除异常", 500, f"{type(e).__name__}: {e}")

        # ---- pins / tags / notes (the tool's own state) --------------------
        if path == "/api/pin":
            agent, sid = body.get("agent", ""), body.get("sid", "")
            if not agent or not sid:
                return self.error_out("缺少 agent 或 sid")
            try:
                if body.get("unpin"):
                    removed = store.unpin(agent, sid)
                    return self.json_out({"ok": True, "pinned": False, "removed": removed})
                store.pin(agent, sid, str(body.get("reason") or ""))
                return self.json_out({"ok": True, "pinned": True, **store.stats_for(agent, sid)})
            except Exception as e:
                return self.error_out("操作保留标记失败", 500, str(e))

        if path == "/api/workspace-pin":
            agent = body.get("agent", "")
            wpath = body.get("path", "")
            if not wpath:
                return self.error_out("缺少 path")
            try:
                if body.get("unpin"):
                    removed = store.unpin_workspace(agent, wpath)
                    return self.json_out({"ok": True, "pinned": False, "removed": removed})
                store.pin_workspace(agent, wpath, str(body.get("reason") or ""))
                return self.json_out(
                    {"ok": True, "pinned": True, "workspace_pins": store.workspace_pins(),
                     **store.counts()}
                )
            except Exception as e:
                return self.error_out("操作工作区保留失败", 500, str(e))

        if path == "/api/tags":
            agent, sid = body.get("agent", ""), body.get("sid", "")
            if not agent or not sid:
                return self.error_out("缺少 agent 或 sid")
            try:
                tags = store.set_tags(agent, sid, body.get("tags") or [])
                return self.json_out({"ok": True, "tags": tags, **store.counts()})
            except Exception as e:
                return self.error_out("设置标签失败", 500, str(e))

        if path == "/api/note":
            agent, sid = body.get("agent", ""), body.get("sid", "")
            if not agent or not sid:
                return self.error_out("缺少 agent 或 sid")
            try:
                note = store.set_note(agent, sid, str(body.get("note") or ""))
                return self.json_out({"ok": True, "note": note})
            except Exception as e:
                return self.error_out("保存备注失败", 500, str(e))

        # ---- export --------------------------------------------------------
        if path == "/api/export":
            agent, sid = body.get("agent", ""), body.get("sid", "")
            if not agent or not sid:
                return self.error_out("缺少 agent 或 sid")
            session = None
            try:
                s = inventory.find(agent, sid)
                if s is not None:
                    session = s.to_dict()
                    store.decorate([session])
            except Exception:
                session = None
            try:
                r = export_mod.export(
                    agent, sid, str(body.get("format") or "markdown"), session
                )
                return self.json_out(r)
            except ValueError as e:
                return self.error_out(str(e), 400)
            except Exception as e:
                return self.error_out("导出失败", 500, f"{type(e).__name__}: {e}")

        # ---- residue cleanup -------------------------------------------------
        # /api/cleanup  { agent, paths?, dispositions?, permanent?, dry_run? }
        if path == "/api/cleanup":
            agent = body.get("agent", "")
            if not agent:
                return self.error_out("缺少 agent")
            paths = body.get("paths")
            if paths is not None and not isinstance(paths, list):
                return self.error_out("paths 必须是数组")
            dispositions = body.get("dispositions")
            if dispositions is not None and not isinstance(dispositions, list):
                return self.error_out("dispositions 必须是数组")
            try:
                r = uninstall.execute_cleanup(
                    agent,
                    paths=paths,
                    dispositions=dispositions,
                    include_data_roots=bool(body.get("include_data_roots")),
                    permanent=bool(body.get("permanent")),
                    dry_run=bool(body.get("dry_run")),
                    force_while_running=bool(body.get("force")),
                )
                return self.json_out({"ok": True, **r})
            except CleanupError as e:
                return self.error_out("清理失败", 409, str(e))
            except Exception as e:
                return self.error_out("清理异常", 500, f"{type(e).__name__}: {e}")

        # /api/registry-delete  { hive, key, dry_run? }
        if path == "/api/registry-delete":
            hive, key = body.get("hive", ""), body.get("reg_key") or body.get("key", "")
            if not hive or not key:
                return self.error_out("缺少 hive 或 reg_key")
            try:
                from core.cleaner import remove_registry_key

                r = remove_registry_key(hive, key, dry_run=bool(body.get("dry_run")))
                return self.json_out({"ok": bool(r.get("ok")), **r})
            except Exception as e:
                return self.error_out("注册表操作失败", 500, f"{type(e).__name__}: {e}")

        # /api/registry-restore  { op_id }
        if path == "/api/registry-restore":
            op_id = body.get("op_id", "")
            if not op_id:
                return self.error_out("缺少 op_id")
            try:
                from core.cleaner import restore_registry_key

                return self.json_out({"ok": True, **restore_registry_key(op_id)})
            except CleanupError as e:
                return self.error_out("还原失败", 409, str(e))
            except Exception as e:
                return self.error_out("还原异常", 500, f"{type(e).__name__}: {e}")

        # /api/uninstall/run  { agent }  -- the only irreversible step
        if path == "/api/uninstall/run":
            agent = body.get("agent", "")
            if not agent:
                return self.error_out("缺少 agent")
            if not body.get("confirm"):
                return self.error_out(
                    "必须显式确认：调用官方卸载器不可撤销，请传入 confirm=true。", 400
                )
            try:
                pf = uninstall.preflight(agent)
                entry = pf.get("uninstall") or {}
                from core.cleaner import run_uninstaller

                # Rebuild the registry entry shape the runner needs.
                r = run_uninstaller(
                    {
                        "quiet_uninstall_string": entry.get("command", "")
                        if entry.get("silent")
                        else "",
                        "uninstall_string": entry.get("command", ""),
                    }
                )
                return self.json_out({"ok": bool(r.get("ok")), **r})
            except Exception as e:
                return self.error_out("启动卸载器失败", 500, f"{type(e).__name__}: {e}")

        # ---- quarantine ------------------------------------------------------
        # /api/quarantine/policy  { retention_days?, max_bytes?, grace_hours?, enabled? }
        if path == "/api/quarantine/policy":
            try:
                changes = {
                    k: body[k]
                    for k in ("retention_days", "max_bytes", "grace_hours", "enabled")
                    if k in body
                }
                return self.json_out({"ok": True, "policy": quarantine.set_policy(**changes)})
            except Exception as e:
                return self.error_out("保存策略失败", 500, str(e))

        # /api/quarantine/purge  { mode?, op_ids? }
        if path == "/api/quarantine/purge":
            op_ids = body.get("op_ids")
            if op_ids is not None and not isinstance(op_ids, list):
                return self.error_out("op_ids 必须是数组")
            try:
                r = quarantine.purge(body.get("mode") or "expired", op_ids=op_ids)
                return self.json_out({"ok": True, **r})
            except Exception as e:
                return self.error_out("清空隔离区失败", 500, str(e))

        # ---- history ---------------------------------------------------------
        if path == "/api/history/record":
            try:
                return self.json_out({"ok": True, **history.record(force=bool(body.get("force")))})
            except Exception as e:
                return self.error_out("记录快照失败", 500, f"{type(e).__name__}: {e}")

        # ---- archive then delete (export -> verify -> delete) ----------------
        # /api/archive-delete  { agent, sid, format?, permanent?, dry_run? }
        if path == "/api/archive-delete":
            agent, sid = body.get("agent", ""), body.get("sid", "")
            if not agent or not sid:
                return self.error_out("缺少 agent 或 sid")
            try:
                fmt = str(body.get("format") or "markdown")
                if body.get("dry_run"):
                    return self.json_out(
                        {
                            "ok": True,
                            "dry_run": True,
                            "note": "预演：将先导出该会话，校验导出文件非空后再删除。",
                            "agent": agent,
                            "sid": sid,
                            "format": fmt,
                        }
                    )
                exp = export_mod.export(agent, sid, fmt)
                path_out = Path(exp.get("path") or "")
                size = path_out.stat().st_size if path_out.exists() else 0
                if size <= 0:
                    return self.error_out(
                        "导出校验失败：导出文件为空，已中止删除。", 409,
                        str(path_out),
                    )
                r = Executor().execute(
                    agent,
                    sid,
                    allow_permanent=bool(body.get("permanent")),
                    allow_unpin=bool(body.get("allow_unpin")),
                )
                return self.json_out(
                    {"ok": True, "export": exp, "export_bytes": size, "delete": r,
                     "note": "已导出并通过非空校验，随后删除。"}
                )
            except ExecutionError as e:
                return self.error_out("归档后删除失败", 409, str(e))
            except ValueError as e:
                return self.error_out(str(e), 400)
            except Exception as e:
                return self.error_out("归档后删除异常", 500, f"{type(e).__name__}: {e}")

        if path == "/api/restore":
            op_id = body.get("op_id", "")
            if not op_id:
                return self.error_out("缺少 op_id")
            try:
                return self.json_out({"ok": True, **Executor.restore(op_id)})
            except ExecutionError as e:
                return self.error_out("还原失败", 409, str(e))
            except Exception as e:
                return self.error_out("还原异常", 500, f"{type(e).__name__}: {e}")

        if path == "/api/batch-delete":
            items = body.get("items") or []
            if not isinstance(items, list):
                return self.error_out("items 必须是数组")
            ex = Executor()
            results = []
            for it in items[:200]:
                agent, sid = it.get("agent", ""), it.get("sid", "")
                try:
                    r = ex.execute(
                        agent,
                        sid,
                        allow_permanent=bool(body.get("permanent")),
                        allow_unpin=bool(body.get("allow_unpin")),
                    )
                    results.append({"agent": agent, "sid": sid, "ok": True,
                                    "op_id": r.get("op_id"), "title": r.get("title")})
                except ExecutionError as e:
                    results.append({"agent": agent, "sid": sid, "ok": False, "error": str(e)})
                except Exception as e:
                    results.append({"agent": agent, "sid": sid, "ok": False,
                                    "error": f"{type(e).__name__}: {e}"})
            ok = sum(1 for r in results if r["ok"])
            return self.json_out({"ok": True, "deleted": ok,
                                  "failed": len(results) - ok, "results": results})

        return self.error_out("未知的接口", 404)

    # ---------------------------------------------------------------- helpers

    def _query(self) -> dict:
        from urllib.parse import parse_qs, urlparse

        return {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}

    def _serve_file(self, p: Path, ctype: str) -> None:
        try:
            body = p.read_bytes()
        except OSError:
            return self.error_out("找不到文件", 404)
        self._send(200, body, ctype)


def main() -> int:
    ap = argparse.ArgumentParser(description="Agent Session Manager (local, read/write)")
    ap.add_argument("--port", type=int, default=8799)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    httpd = ThreadingHTTPServer((HOST, args.port), Handler)
    url = f"http://{HOST}:{args.port}/"

    print("=" * 72)
    print("  Agent 会话管理器 —— 本地可视化会话管理工具")
    print("=" * 72)
    print(f"  地址      : {url}")
    print(f"  数据目录  : {Path(__file__).resolve().parent / '_data'}")
    print(f"  平台      : {plat()}")
    print()
    print("  仅监听本机回环地址，不联网、不上传任何数据。")
    print("  删除默认进入隔离区（可一键还原），不会永久删除。")
    print()
    print("  按 Ctrl+C 停止服务。")
    print("=" * 72)

    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n正在停止……")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
