"""Command-line interface.

The same core the web UI uses, exposed for scripting and for batch work. It
deliberately mirrors the UI's safety model rather than offering a shortcut
around it:

  * every destructive command has ``--dry-run`` and prints what it would do
  * ``delete`` requires ``--yes``; ``uninstall`` requires ``--yes`` *and* is the
    only command that can touch an installed product
  * ``--json`` makes every command emit machine-readable output
  * exit codes are meaningful: 0 success, 1 error, 2 refused by a safety check,
    so a script can distinguish "failed" from "would not do that"

Usage:
    python cli.py scan
    python cli.py sessions --agent dsh
    python cli.py plan --agent dsh --sid <id>
    python cli.py delete --agent dsh --sid <id> --yes
    python cli.py residue --agent workbuddy
    python cli.py cleanup --agent workbuddy --dry-run
    python cli.py uninstall --agent workbuddy --yes
    python cli.py quarantine
    python cli.py history --record
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_REFUSED = 2


def emit(args, obj, human: str = "") -> None:
    """Print either JSON or a human summary."""
    if getattr(args, "json", False):
        print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))
    elif human:
        print(human)
    else:
        print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))


def _hsize(n) -> str:
    from core.util import human_size

    return human_size(n)


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def cmd_scan(args) -> int:
    from core import inventory

    sessions = inventory.scan(force=True)
    rep = inventory.report(force=True)
    rows = [
        {
            "agent": a["id"],
            "label": a["label"],
            "installed": a["installed"],
            "sessions": a["session_count"],
            "bytes": a["size"],
            "bytes_h": _hsize(a["size"]),
            "files": a["file_count"],
        }
        for a in rep["agents"]
    ]
    if args.json:
        emit(args, {"agents": rows, "sessions": len(sessions)})
        return EXIT_OK

    out = [f"{'Agent':<18}{'会话':>6}{'占用':>12}{'文件':>9}  状态"]
    for r in rows:
        out.append(
            f"{r['agent']:<18}{r['sessions']:>6}{r['bytes_h']:>12}{r['files']:>9}"
            f"  {'已安装' if r['installed'] else '未检测到'}"
        )
    total = sum(r["bytes"] for r in rows)
    out.append(f"\n共 {len(sessions)} 个会话，{_hsize(total)}。")
    print("\n".join(out))
    return EXIT_OK


def cmd_sessions(args) -> int:
    from core import inventory, store

    sessions = [s.to_dict() for s in inventory.scan()]
    store.decorate(sessions)
    if args.agent:
        sessions = [s for s in sessions if s["agent"] == args.agent]
    if args.pinned:
        sessions = [s for s in sessions if s.get("pinned") or s.get("protected")]
    if args.json:
        emit(args, {"count": len(sessions), "sessions": sessions})
        return EXIT_OK

    out = [
        f"{'Agent':<14}{'会话 ID':<40}{'占用':>10}  {'更新时间':<20} 标题"
    ]
    for s in sessions[: args.limit]:
        flag = "🔒" if s.get("protected") else "  "
        out.append(
            f"{s['agent']:<14}{s['sid'][:38]:<40}{s.get('size_h', ''):>10}  "
            f"{s.get('updated_iso', '')[:19]:<20}{flag}{s.get('title', '')[:40]}"
        )
    if len(sessions) > args.limit:
        out.append(f"\n（共 {len(sessions)} 个，仅显示前 {args.limit} 个；用 --limit 调整）")
    else:
        out.append(f"\n共 {len(sessions)} 个会话。")
    print("\n".join(out))
    return EXIT_OK


def cmd_plan(args) -> int:
    from adapters.registry import get_adapter
    from core import inventory, store
    from core.executor import Executor, plan_fingerprint

    adapter = get_adapter(args.agent)
    if adapter is None:
        print(f"未知的 Agent：{args.agent}", file=sys.stderr)
        return EXIT_ERROR
    plan = adapter.plan_delete(args.sid)
    problems = Executor.validate(plan, adapter)
    payload = plan.to_dict()
    payload["validation_problems"] = problems
    payload["fingerprint"] = plan_fingerprint(plan)
    payload["pinned"] = store.is_pinned(args.agent, args.sid)

    if args.json:
        emit(args, payload)
        return EXIT_OK

    print(f"Agent : {plan.agent_label} ({plan.agent})")
    print(f"会话  : {plan.sid}")
    print(f"标题  : {plan.title or '(无)'}")
    print(f"指纹  : {plan_fingerprint(plan)}")
    print(f"可执行: {'否' if (plan.blocked or problems) else '是'}")
    if plan.blocked:
        print(f"阻止  : {plan.block_reason}")
    for p in problems:
        print(f"问题  : {p}")
    for w in plan.warnings:
        print(f"警告  : {w}")
    print(f"\n将执行 {len(plan.actions)} 个动作，共 {_hsize(plan.total_size)}：")
    for a in plan.actions:
        print(f"  [{a.kind}] {a.path}  {_hsize(a.size) if a.size else ''}"
              f"{'  → ' + a.table if a.table else ''}")
    if plan.optional_actions:
        print(f"\n可选动作 {len(plan.optional_actions)} 个（需 --include-attachments）：")
        for a in plan.optional_actions:
            print(f"  [{a.kind}] {a.path}  {_hsize(a.size) if a.size else ''}")
    return EXIT_OK


def cmd_delete(args) -> int:
    from core.executor import ExecutionError, Executor, plan_fingerprint
    from adapters.registry import get_adapter

    if not args.yes:
        print(
            "拒绝执行：删除是破坏性操作，需要显式确认。请加 --yes 后重试。\n"
            "建议先用 `python cli.py plan --agent ... --sid ...` 审阅计划。",
            file=sys.stderr,
        )
        return EXIT_REFUSED

    fp = ""
    if not args.skip_fingerprint:
        adapter = get_adapter(args.agent)
        if adapter is not None:
            fp = plan_fingerprint(adapter.plan_delete(args.sid))

    try:
        r = Executor().execute(
            args.agent,
            args.sid,
            allow_permanent=bool(getattr(args, "permanent", False)),
            include_attachments=bool(getattr(args, "include_attachments", False)),
            allow_unpin=bool(getattr(args, "allow_unpin", False)),
            expected_fingerprint=fp,
        )
    except ExecutionError as e:
        print(f"删除被拒绝：{e}", file=sys.stderr)
        return EXIT_REFUSED

    if args.json:
        emit(args, r)
    else:
        print(f"已删除：{r.get('title') or r.get('sid')}")
        print(f"操作编号：{r['op_id']}   （可用 `python cli.py restore --op-id {r['op_id']}` 还原）")
        print(f"校验    ：{r.get('verify_message', '')}")
        print(f"隔离区  ：{r.get('quarantine', '')}")
    return EXIT_OK


def cmd_restore(args) -> int:
    from core.executor import ExecutionError, Executor

    try:
        r = Executor.restore(args.op_id)
    except ExecutionError as e:
        print(f"还原失败：{e}", file=sys.stderr)
        return EXIT_ERROR
    if args.json:
        emit(args, r)
    else:
        print(f"已还原：{r.get('restored', 0)} 个路径，{r.get('rows', 0)} 行数据")
    return EXIT_OK


def cmd_batch_delete(args) -> int:
    from core.executor import ExecutionError, Executor

    if not args.yes:
        print("拒绝执行：需要 --yes。", file=sys.stderr)
        return EXIT_REFUSED

    from core import inventory

    sessions = inventory.scan()
    victims = [s for s in sessions if s.agent == args.agent] if args.agent else sessions
    if args.only_residue:
        victims = [s for s in victims if s.is_ghost or s.is_orphan]
    if args.limit:
        victims = victims[: args.limit]

    if args.dry_run:
        rows = [
            {"agent": s.agent, "sid": s.sid, "title": s.title, "size_h": _hsize(s.size)}
            for s in victims
        ]
        emit(args, {"dry_run": True, "count": len(victims), "items": rows},
             f"预演：将删除 {len(victims)} 个会话（未做任何修改）。")
        return EXIT_OK

    ex = Executor()
    ok = 0
    failed = []
    for s in victims:
        try:
            ex.execute(args.agent or s.agent, s.sid, allow_unpin=args.allow_unpin)
            ok += 1
        except Exception as e:
            failed.append({"agent": s.agent, "sid": s.sid, "error": str(e)})
    if args.json:
        emit(args, {"deleted": ok, "failed": len(failed), "errors": failed})
    else:
        print(f"已删除 {ok} 个，失败 {len(failed)} 个。")
        for f in failed[:20]:
            print(f"  {f['agent']} {f['sid'][:40]}: {f['error'][:80]}")
    return EXIT_OK if not failed else EXIT_ERROR


def cmd_residue(args) -> int:
    from core import residue

    if args.agent:
        r = residue.scan_agent(args.agent)
        if args.json:
            emit(args, r)
            return EXIT_OK
        s = r["summary"]
        print(f"=== {r['label']} ({r['agent']}) 残留报告 ===")
        print(f"  可安全清理 : {s['safe_count']} 项，{s['safe_bytes_h']}")
        print(f"  需人工确认 : {s['review_count']} 项，{s['review_bytes_h']}")
        print(f"  禁止删除   : {s['never_count']} 项，{s['never_bytes_h']}")
        print(f"  密钥/凭据  : {s['credential_count']} 项")
        print(f"  临时目录   : {s['temp_count']} 项，{s['temp_bytes_h']}")
        print(f"  注册表     : {s['registry_keys']} 项（可删 {s['removable_registry_keys']}）")
        print(f"  防火墙     : {s['firewall_rules']} 条  快捷方式 {s['shortcuts']} 个"
              f"（孤立 {s['orphan_shortcuts']}）")
        print(f"  需要管理员 : {'是' if s['needs_admin'] else '否'}")
        if s["credential_count"]:
            print("\n  密钥文件：")
            for c in r["credentials"][:10]:
                print(f"    {c['path']}")
        print("\n  可安全清理的项：")
        for f in [x for x in r["files"] if x["disposition"] == "safe"][: args.limit]:
            print(f"    {f['size_h']:>10}  {f['path']}")
        return EXIT_OK

    allr = residue.scan_all_agents()
    if args.json:
        emit(args, allr)
        return EXIT_OK
    print(f"{'Agent':<16}{'可安全清理':>12}{'需确认':>12}{'密钥':>6}")
    for a in allr["agents"]:
        s = a.get("summary") or {}
        if not s:
            print(f"{a['agent']:<16}{'扫描失败':>12}")
            continue
        print(f"{a['agent']:<16}{s.get('safe_bytes_h', '0 B'):>12}"
              f"{s.get('review_bytes_h', '0 B'):>12}{s.get('credential_count', 0):>6}")
    return EXIT_OK


def cmd_cleanup(args) -> int:
    from core import uninstall
    from core.cleaner import CleanupError

    plan = uninstall.cleanup_plan(args.agent)
    if args.list:
        for bucket in ("safe", "review", "never"):
            print(f"\n--- {bucket} ({len(plan[bucket])}) ---")
            for i in plan[bucket]:
                print(f"  {str(i.get('size_h') or ''):>10}  {i['path']}")
                if bucket == "never":
                    print(f"              ↳ {i.get('evidence', '')}")
        print(f"\n{plan['note']}")
        return EXIT_OK

    dispositions = args.dispositions or ["safe"]
    try:
        r = uninstall.execute_cleanup(
            args.agent,
            dispositions=dispositions,
            include_data_roots=args.include_data_roots,
            permanent=args.permanent,
            dry_run=args.dry_run,
            force_while_running=args.force,
        )
    except CleanupError as e:
        print(f"清理被拒绝：{e}", file=sys.stderr)
        return EXIT_REFUSED

    if args.json:
        emit(args, r)
    else:
        print(r["note"])
        if r.get("needs_admin"):
            print("\n以下项目需要管理员权限，请自行在管理员 PowerShell 中执行：")
            for c in r["needs_admin"]:
                print(f"  {c['command']}")
        f = r.get("file_ops") or {}
        for res in (f.get("results") or [])[:40]:
            mark = "✓" if res.get("ok") else "✗"
            print(f"  {mark} {res.get('path')}"
                  + ("" if res.get("ok") else f"  {res.get('error', '')}"))
    return EXIT_OK


def cmd_uninstall(args) -> int:
    from core import uninstall
    from core.cleaner import run_uninstaller

    pf = uninstall.preflight(args.agent)
    if args.preflight_only or not args.yes:
        if args.json:
            emit(args, pf)
        else:
            print(f"=== {pf['label']} ({pf['agent']}) 卸载预检 ===")
            print(f"  已安装     : {'是' if pf['installed'] else '否'}")
            print(f"  可继续     : {'是' if pf['can_proceed'] else '否'}")
            u = pf["uninstall"]
            print(f"  注册表条目 : {u.get('registry_name') or '(未找到)'} {u.get('version') or ''}")
            print(f"  卸载命令   : {u.get('command') or '(无)'}")
            print(f"  静默支持   : {'是' if u.get('silent') else '否'}")
            print(f"  会话       : {pf['sessions']['count']} 个（保留 {pf['sessions']['pinned']}）")
            s = pf["residue"]["summary"]
            print(f"  残留       : 可清理 {s.get('safe_bytes_h')}，需确认 {s.get('review_bytes_h')}")
            print(f"  密钥       : {len(pf['credentials'])} 个")
            print(f"  需要管理员 : {'是' if pf['windows']['needs_admin'] else '否'}"
                  f"（当前{'已' if pf['elevated'] else '未'}提权）")
            for b in pf["blockers"]:
                print(f"\n  ⚠ {b['title']}\n    {b['detail']}\n    → {b['action']}")
            if not args.yes:
                print("\n这是预检结果。要真正调用官方卸载器，请加 --yes。")
                print("注意：调用卸载器不可撤销。")
        return EXIT_OK

    if not pf["uninstall"].get("found"):
        print("注册表中没有找到该产品的卸载条目，无法调用官方卸载器。", file=sys.stderr)
        print("请从「设置 → 应用」中卸载，或使用 `python cli.py cleanup` 清理残留。",
              file=sys.stderr)
        return EXIT_ERROR
    if not pf["can_proceed"]:
        print("预检未通过：", file=sys.stderr)
        for b in pf["blockers"]:
            print(f"  - {b['title']}：{b['action']}", file=sys.stderr)
        return EXIT_REFUSED

    entry = {
        "quiet_uninstall_string": pf["uninstall"]["command"]
        if pf["uninstall"].get("silent")
        else "",
        "uninstall_string": pf["uninstall"]["command"],
    }
    print(f"正在调用官方卸载器：{pf['uninstall']['command']}")
    r = run_uninstaller(entry)
    if args.json:
        emit(args, r)
    else:
        print(r.get("note") or r.get("error", ""))
        if r.get("exit_code") is not None:
            print(f"退出码：{r['exit_code']}")
    if not r.get("ok"):
        return EXIT_ERROR

    if args.cleanup_after:
        print("\n卸载器已结束，正在重新扫描残留……")
        v = uninstall.verify(args.agent)
        print(v["note"])
        print(f"  仍可回收：{v['reclaimable_bytes_h']}")
        if args.json:
            emit(args, v)
    return EXIT_OK


def cmd_verify(args) -> int:
    from core import uninstall

    r = uninstall.verify(args.agent)
    if args.json:
        emit(args, r)
        return EXIT_OK
    print(f"=== {args.agent} 卸载后验证 ===")
    print(f"  仍然安装   : {'是' if r['still_installed'] else '否'}")
    print(f"  注册表条目 : {'仍在' if r['uninstall_entry_present'] else '已清除'}")
    print(f"  仍可回收   : {r['reclaimable_bytes_h']}")
    print(f"  剩余项目   : {r['remaining_items']} 项，{r['remaining_bytes_h']}")
    print(f"  密钥残留   : {r['credentials_left']} 个")
    print(f"  需要管理员 : {'是' if r['needs_admin'] else '否'}")
    print(f"\n{r['note']}")
    return EXIT_OK


def cmd_quarantine(args) -> int:
    from core import quarantine

    if args.set_retention_days is not None or args.set_max_gb is not None:
        changes = {}
        if args.set_retention_days is not None:
            changes["retention_days"] = args.set_retention_days
        if args.set_max_gb is not None:
            changes["max_bytes"] = int(args.set_max_gb * 1024 ** 3)
        p = quarantine.set_policy(**changes)
        if args.json:
            emit(args, p)
        else:
            print("策略已更新：")
            print(f"  保留天数 : {p['retention_days']}")
            print(f"  容量上限 : {_hsize(p['max_bytes'])}")
            print(f"  保护期   : {p['grace_hours']} 小时")
        return EXIT_OK

    if args.purge:
        if not args.yes and not args.dry_run:
            print("拒绝执行：清空隔离区不可撤销，需要 --yes。", file=sys.stderr)
            return EXIT_REFUSED
        if args.dry_run:
            p = quarantine.plan_purge(args.mode)
            emit(args, p, f"预演：将清空 {p['count']} 项，释放 {p['bytes_h']}。{p['note']}")
            return EXIT_OK
        r = quarantine.purge(args.mode)
        if args.json:
            emit(args, r)
        else:
            print(f"已清空 {r['purged']} 项，释放 {r['freed_bytes_h']}。")
            for x in r["results"]:
                if not x["ok"]:
                    print(f"  ✗ {x['op_id']}: {x['error']}")
        return EXIT_OK

    st = quarantine.stats()
    if args.json:
        emit(args, st)
        return EXIT_OK
    print("=== 隔离区 ===")
    print(f"  条目     : {st['entry_count']} 项")
    print(f"  占用     : {st['total_bytes_h']} / {st['max_bytes_h']}（{st['usage_pct']}%）")
    print(f"  已过期   : {st['expired_count']} 项，{st['expired_bytes_h']}")
    if st["over_cap"]:
        print(f"  超出上限 : {st['over_cap_bytes_h']}（将按最旧优先清除）")
    pol = st["policy"]
    print(f"  策略     : 保留 {pol['retention_days']} 天，上限 {_hsize(pol['max_bytes'])}，"
          f"保护期 {pol['grace_hours']} 小时，自动清理{'开启' if pol['enabled'] else '关闭'}")
    if st["entries"]:
        print(f"\n  {'操作编号':<28}{'占用':>10}  {'天数':>6}  标题")
        for e in st["entries"][: args.limit]:
            print(f"  {e['op_id']:<28}{e['size_h']:>10}  {e['age_days']:>6.1f}  "
                  f"{e.get('title', '')[:36]}")
    return EXIT_OK


def cmd_history(args) -> int:
    from core import history

    if args.record:
        r = history.record(force=args.force)
        if args.json:
            emit(args, r)
        else:
            if r.get("recorded"):
                print("已记录快照：")
                for k, v in (r.get("agents") or {}).items():
                    print(f"  {k:<16}{_hsize(v['bytes']):>12}  {v['files']} 个文件")
            else:
                print(f"未记录：{r.get('reason', '')}")
        return EXIT_OK

    if args.prune:
        n = history.prune(keep_days=args.keep_days)
        print(f"已清理 {n} 条过期快照。")
        return EXIT_OK

    t = history.trend(args.agent, days=args.days)
    s = history.summarize()
    if args.json:
        emit(args, {"summary": s, "trend": t})
        return EXIT_OK
    print("=== 占用增长趋势 ===")
    print(f"  快照数量 : {s['snapshots']}，跨度 {s['span_days']:.1f} 天")
    if t.get("insufficient"):
        print(f"  {t.get('note', '')}")
    else:
        print(f"  当前     : {_hsize(t['last_bytes'])}")
        print(f"  变化     : {_hsize(t['delta_bytes'])}")
        print(f"  日均     : {_hsize(t['per_day_bytes'])}")
        if t.get("projection_days") is not None:
            print(f"  预计     : 约 {t['projection_days']} 天后达到 "
                  f"{_hsize(t['projection_target_bytes'])}")
        else:
            print(f"  {t.get('note', '')}")
    return EXIT_OK


def cmd_dupes(args) -> int:
    from core import dupes

    r = dupes.find(min_bytes=args.min_kb * 1024)
    if args.json:
        emit(args, r)
        return EXIT_OK
    print("=== 重复内容检测（只读）===")
    print(f"  扫描文件 : {r['scanned_files']}")
    print(f"  候选文件 : {r['candidate_files']}")
    print(f"  重复组   : {len(r['groups'])}")
    print(f"  可回收   : {r['wasted_bytes_h']}")
    if r.get("note"):
        print(f"  {r['note']}")
    for g in r["groups"][: args.limit]:
        print(f"\n  [{g['kind']}] {g['count']} 份，每份 {g['size_h']}，浪费 {g['wasted_h']}")
        for p in g["paths"][:4]:
            print(f"    {p['path']}")
    print("\n注意：本命令只报告，不会删除任何文件。")
    return EXIT_OK


def cmd_secrets(args) -> int:
    from core import inventory, secrets

    if args.agent and args.sid:
        r = secrets.scan_session(args.agent, args.sid)
        if args.json:
            emit(args, r)
            return EXIT_OK
        if not r.get("available"):
            print(f"无法读取该会话内容：{r.get('reason', '')}")
            return EXIT_OK
        print(f"=== {args.agent} / {args.sid} 敏感信息扫描 ===")
        print(f"  命中 {r['total']} 处：高危 {r['counts']['high']}，"
              f"中危 {r['counts']['medium']}，低危 {r['counts']['low']}")
        for h in r["hits"][: args.limit]:
            print(f"  [{h['severity']:<6}] {h['label']:<20} {h['preview']}")
        return EXIT_OK

    sessions = [s.to_dict() for s in inventory.scan()]
    r = secrets.scan_sessions(sessions)
    if args.json:
        emit(args, r)
        return EXIT_OK
    print("=== 全部会话敏感信息扫描 ===")
    print(f"  已扫描 : {r['scanned']} 个会话，无法读取 {r['unavailable']} 个")
    print(f"  命中   : {r['total_hits']} 处")
    for k, v in (r.get("by_severity") or {}).items():
        print(f"    {k}: {v}")
    for x in r["results"][: args.limit]:
        print(f"\n  {x['agent']} / {x['sid'][:40]} — {x['total']} 处")
        for h in x["hits"][:5]:
            print(f"    [{h['severity']:<6}] {h['preview']}")
    print(f"\n{r.get('note', '')}")
    return EXIT_OK


def cmd_projects(args) -> int:
    from core import inventory, projects, store, usage

    sessions = [s.to_dict() for s in inventory.scan()]
    store.decorate(sessions)
    usage_by = {}
    for s in sessions:
        try:
            usage_by[f"{s['agent']}|{s['sid']}"] = usage.for_session(s["agent"], s["sid"])
        except Exception:
            continue
    r = projects.group(sessions, None, usage_by)
    if args.json:
        emit(args, r)
        return EXIT_OK
    print("=== 按项目聚合 ===")
    print(f"  项目数 : {r['total_projects']}，未记录工作目录 {r['unassigned']} 个")
    for p in r["projects"][: args.limit]:
        agents = "、".join(p["agents"])
        print(f"\n  {p['label']}  ({p['session_count']} 个会话，{p['total_bytes_h']})")
        print(f"    路径   : {p['path']}")
        print(f"    Agent  : {agents}")
        if p.get("protected_count"):
            print(f"    受保护 : {p['protected_count']} 个")
        if p.get("junk_count"):
            print(f"    低价值 : {p['junk_count']} 个")
    return EXIT_OK


def cmd_admin(args) -> int:
    """Do the handful of things that genuinely need Administrator."""
    from core import elevate

    p = elevate.plan(args.agent)
    if not p["actions"]:
        print("本机没有需要管理员权限的残留项。")
        return EXIT_OK

    print(f"=== {args.agent} 需要管理员权限的项目：{p['count']} 项 ===")
    for i, a in enumerate(p["actions"], 1):
        print("  %d. %-12s %s" % (i, a["kind"], a["target"]))
        print("     %s" % a["reason"])
    print()
    if p["already_elevated"]:
        print("当前已是管理员权限，无需提权；请直接用 `cleanup` 清理即可。")
        return EXIT_OK

    if args.show_script:
        print("--- 将以管理员身份运行的 PowerShell 脚本 ---")
        print(p["script"])
        print("--- 脚本结束 ---")
        return EXIT_OK

    if not args.yes:
        print("这是预检结果。要真正执行并弹出 UAC 授权窗口，请加 --yes。")
        print("提示：加 --show-script 可先查看将要运行的完整脚本。")
        print("注意：每项在删除前都会把备份写入隔离区；取消 UAC 不会修改任何东西。")
        return EXIT_OK

    only = args.only or None
    # Validate the narrowing *before* announcing a UAC prompt: a target outside
    # the agent's inventory must fail visibly, not after looking like it started.
    if only:
        allowed = {a["target"] for a in p["actions"]}
        rejected = [t for t in only if t not in allowed]
        if rejected:
            print("拒绝执行：以下目标不在该 Agent 的可提权清单中：", file=sys.stderr)
            for t in rejected:
                print("  - %s" % t, file=sys.stderr)
            print("可提权的目标只有：", file=sys.stderr)
            for a in p["actions"]:
                print("  - %s" % a["target"], file=sys.stderr)
            return EXIT_REFUSED

    print("正在请求管理员权限（请在 UAC 窗口中确认）…")
    r = elevate.execute(args.agent, confirm=True, only=only)

    if args.json:
        emit(args, r)
    else:
        if r.get("cancelled"):
            print("已取消：你拒绝了 UAC 授权，未做任何修改。")
            return EXIT_REFUSED
        if not r.get("elevated"):
            print("未能提权：%s" % (r.get("error") or "未知原因"), file=sys.stderr)
            return EXIT_ERROR
        ok = [x for x in r.get("results", []) if x.get("ok")]
        bad = [x for x in r.get("results", []) if not x.get("ok")]
        print("成功 %d 项，失败 %d 项。" % (len(ok), len(bad)))
        for x in r.get("results", []):
            mark = "✓" if x.get("ok") else "✗"
            note = x.get("error") or x.get("note") or ""
            print("  %s [%s] %s  %s" % (mark, x.get("kind"), str(x.get("target"))[:60], note))
        if r.get("backup_dir"):
            print("\n备份位置：%s" % r["backup_dir"])
            print("注册表可用 reg import 还原；快捷方式可直接复制回去。")
    return EXIT_OK if r.get("ok") else EXIT_ERROR


def cmd_capabilities(args) -> int:
    """What this tool can and cannot clean, and why. Read-only.

    Exists because "did it uninstall completely?" deserves a straight answer
    rather than a green checkmark.
    """
    from core import elevate, uninstall

    env = __import__("core.wininteg", fromlist=["x"]).environment_summary()
    r = uninstall.full_report()
    if args.json:
        emit(args, {"elevated": env["elevated"], "agents": r["agents"],
                    "privileged": {a["agent"]: elevate.plan(a["agent"])["count"]
                                   for a in r["agents"]}})
        return EXIT_OK

    print("=== 清理能力与边界 ===")
    print("  当前权限: %s" % ("管理员" if env["elevated"] else "普通用户（部分项目需提权）"))
    print()
    print("  %-16s %-12s %-12s %s" % ("Agent", "可安全清理", "需人工确认", "需管理员"))
    for a in r["agents"]:
        n = elevate.plan(a["agent"])["count"]
        print("  %-16s %-12s %-12s %d"
              % (a["agent"], a.get("reclaimable_bytes_h", "—"),
                 a.get("review_bytes_h", "—"), n))
    print()
    print("本工具会清理：")
    for line in (
        "会话记录（按适配器分别处理文件 / SQLite 行 / 索引条目）",
        "可再生缓存、日志、临时目录、空壳目录",
        "密钥/凭据文件（单独列出，默认不勾选）",
        "HKCU 注册表厂商键（删除前导出 .reg 备份）",
        "开始菜单 / 桌面快捷方式（移入隔离区，可还原）",
        "防火墙规则、HKLM 注册表键、ProgramData 快捷方式（需提权，见 admin-cleanup）",
    ):
        print("  · " + line)
    print()
    print("本工具不清理（以及原因）：")
    for line in (
        "程序安装目录 —— 交给官方卸载器，手工删会留下更多注册表残渣",
        "凭据管理器（cmdkey）—— 尚未实现扫描",
        "环境变量 PATH 条目 —— 尚未实现扫描",
        "App Paths / 文件关联 / 协议处理器 —— 尚未实现扫描",
        "系统服务与计划任务 —— 只报告，删除可能影响系统，需人工判断",
    ):
        print("  · " + line)
    return EXIT_OK


def cmd_report(args) -> int:
    from core import uninstall

    r = uninstall.full_report()
    if args.json:
        emit(args, r)
        return EXIT_OK
    print("=== 各 Agent 卸载/回收概览 ===")
    print(f"{'Agent':<18}{'可回收':>12}{'需确认':>12}{'禁止':>12}{'密钥':>6}")
    for a in r["agents"]:
        print(f"{a['agent']:<18}{a.get('reclaimable_bytes_h', '—'):>12}"
              f"{a.get('review_bytes_h', '—'):>12}{a.get('never_bytes_h', '—'):>12}"
              f"{a.get('credentials', 0):>6}")
    print(f"\n合计可安全回收：{r['total_reclaimable_h']}")
    return EXIT_OK


# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="cli.py",
        description="Agent 会话管理器 —— 命令行模式（与图形界面共用同一套安全机制）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "退出码：0 成功，1 错误，2 被安全检查拒绝。\n"
            "所有破坏性命令都支持 --dry-run，且需要 --yes 才会真正执行。"
        ),
    )
    ap.add_argument("--json", action="store_true", help="输出 JSON，便于脚本处理")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scan", help="扫描所有已安装 Agent 的会话与占用")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("sessions", help="列出会话")
    p.add_argument("--agent", default="", help="只看某个 Agent")
    p.add_argument("--pinned", action="store_true", help="只看被标记「保留」的")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=cmd_sessions)

    p = sub.add_parser("plan", help="查看删除某个会话会做什么（只读）")
    p.add_argument("--agent", required=True)
    p.add_argument("--sid", required=True)
    p.set_defaults(func=cmd_plan)

    p = sub.add_parser("delete", help="删除指定会话（需 --yes）")
    p.add_argument("--agent", required=True)
    p.add_argument("--sid", required=True)
    p.add_argument("--yes", action="store_true", help="确认执行")
    p.add_argument("--permanent", action="store_true", help="永久删除，不进隔离区")
    p.add_argument("--include-attachments", action="store_true", help="同时删除无引用附件")
    p.add_argument("--allow-unpin", action="store_true", help="忽略「保留」标记")
    p.add_argument("--skip-fingerprint", action="store_true",
                   help="跳过指纹校验（不推荐）")
    p.set_defaults(func=cmd_delete)

    p = sub.add_parser("restore", help="按操作编号还原已删除的会话")
    p.add_argument("--op-id", required=True)
    p.set_defaults(func=cmd_restore)

    p = sub.add_parser("batch-delete", help="批量删除（需 --yes）")
    p.add_argument("--agent", default="")
    p.add_argument("--only-residue", action="store_true", help="只删幽灵/孤儿会话")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--yes", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--allow-unpin", action="store_true")
    p.set_defaults(func=cmd_batch_delete)

    p = sub.add_parser("residue", help="扫描残留（只读）")
    p.add_argument("--agent", default="", help="不填则汇总所有 Agent")
    p.add_argument("--limit", type=int, default=30)
    p.set_defaults(func=cmd_residue)

    p = sub.add_parser("cleanup", help="清理残留")
    p.add_argument("--agent", required=True)
    p.add_argument("--list", action="store_true", help="只列出，不清理")
    p.add_argument("--dispositions", nargs="*", choices=["safe", "review"],
                   help="要清理的等级，默认 safe")
    p.add_argument("--include-data-roots", action="store_true",
                   help="同时删除该 Agent 的数据根目录（不可逆，需谨慎）")
    p.add_argument("--permanent", action="store_true", help="不进隔离区")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--force", action="store_true", help="即使 Agent 正在运行也继续")
    p.set_defaults(func=cmd_cleanup)

    p = sub.add_parser("uninstall", help="调用官方卸载器（不可撤销）")
    p.add_argument("--agent", required=True)
    p.add_argument("--yes", action="store_true", help="确认调用卸载器")
    p.add_argument("--preflight-only", action="store_true", help="只做预检")
    p.add_argument("--cleanup-after", action="store_true", help="卸载后自动验证残留")
    p.set_defaults(func=cmd_uninstall)

    p = sub.add_parser("verify", help="卸载后验证残留")
    p.add_argument("--agent", required=True)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("quarantine", help="查看/设置隔离区保留策略")
    p.add_argument("--purge", action="store_true", help="清空隔离区")
    p.add_argument("--mode", default="expired", choices=["expired", "over_cap", "all"])
    p.add_argument("--yes", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--set-retention-days", type=int, default=None)
    p.add_argument("--set-max-gb", type=float, default=None)
    p.add_argument("--limit", type=int, default=30)
    p.set_defaults(func=cmd_quarantine)

    p = sub.add_parser("history", help="占用增长趋势")
    p.add_argument("--agent", default="")
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--record", action="store_true", help="记录一次快照")
    p.add_argument("--force", action="store_true", help="强制记录（忽略频率限制）")
    p.add_argument("--prune", action="store_true", help="清理过期快照")
    p.add_argument("--keep-days", type=int, default=365)
    p.set_defaults(func=cmd_history)

    p = sub.add_parser("dupes", help="查找重复内容（只读）")
    p.add_argument("--min-kb", type=int, default=4, help="最小文件大小（KB）")
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_dupes)

    p = sub.add_parser("secrets", help="扫描会话中的敏感信息（只读）")
    p.add_argument("--agent", default="")
    p.add_argument("--sid", default="")
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_secrets)

    p = sub.add_parser("projects", help="按项目聚合会话")
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_projects)

    p = sub.add_parser("admin-cleanup",
                       help="以管理员身份完成需要提权的残留清理（会弹 UAC）")
    p.add_argument("--agent", required=True)
    p.add_argument("--yes", action="store_true", help="确认执行并弹出 UAC 授权")
    p.add_argument("--show-script", action="store_true",
                   help="只打印将要以管理员身份运行的完整脚本")
    p.add_argument("--only", nargs="*", default=None,
                   help="只处理指定目标（不能超出该 Agent 的清单）")
    p.set_defaults(func=cmd_admin)

    p = sub.add_parser("capabilities",
                       help="本工具能清理什么、不能清理什么（只读）")
    p.set_defaults(func=cmd_capabilities)

    p = sub.add_parser("report", help="各 Agent 卸载/回收概览")
    p.set_defaults(func=cmd_report)

    return ap


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n已中断。", file=sys.stderr)
        return EXIT_ERROR
    except Exception as e:
        print(f"错误：{type(e).__name__}: {e}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
