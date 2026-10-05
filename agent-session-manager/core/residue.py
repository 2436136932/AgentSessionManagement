"""Residue scanner: what is left of an agent after it is uninstalled.

The point of this module is to answer, for one agent, "if I get rid of this,
what exactly is still on my machine?" -- and to answer it with *evidence*
rather than with a keyword guess.

It gathers findings from every surface in one pass:

  ==================  =====================================================
  surface             why it exists
  ==================  =====================================================
  files               declared roots, plus the vendor-scoped containers no
                      adapter knows about, plus empty shells
  registry (product)  the uninstall entry itself, and whether it survived
  registry (vendor)   ``HKCU\\SOFTWARE\\<vendor>`` settings
  firewall            named rules the installer added
  shortcuts           Start Menu / Desktop links, orphaned ones flagged
  services/tasks      things that would try to launch a deleted program
  autostart           Run-key entries pointing at a deleted program
  temporary           ``%TEMP%\\<prefix>*`` working directories
  credentials         key material that outlives the program
  ==================  =====================================================

Every finding carries a ``disposition`` (see :mod:`core.ownership`) and an
``evidence`` string. Nothing here deletes anything: the executor does that,
after a human picks the items.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

from core import wininteg
from core.ownership import (
    NEVER,
    REVIEW,
    SAFE,
    Classifier,
    _norm,
    drill_down,
)
from core.util import home, local_appdata, roaming_appdata

# --------------------------------------------------------------------------
# Known container shapes that no adapter declares
# --------------------------------------------------------------------------
# Each entry maps a filesystem container to the agent it belongs to. These are
# the leftovers that a per-adapter model cannot see, because the adapter only
# knows the *data* directory it reads -- not the Electron profile, the WebView2
# cache or the extension folder sitting next to it.
#
# `path` is relative to `base`; `owner` is an adapter id when one exists, else
# a free-form label. `expect` says why we believe it belongs to that agent.
KNOWN_CONTAINERS: list[dict] = [
    {
        "owner": "dsh",
        "base": "roaming",
        "path": "@deepseek-ai",
        "expect": "Electron 用户数据目录，含 dsh-desktop 的缓存与登录态",
    },
    {
        "owner": "codebuddy",
        "base": "local",
        "path": "CodeBuddyExtension",
        "expect": "VS Code 扩展的本地数据与日志目录",
    },
    {
        "owner": "codebuddy",
        "base": "home",
        "path": ".codebuddy",
        "expect": "CodeBuddy 命令行配置与插件目录",
    },
    {
        "owner": "antigravity",
        "base": "local",
        "path": "com.lbjlaq.antigravity-tools",
        "expect": "WebView2 用户数据目录（反域名包名）",
    },
    {
        "owner": "antigravity",
        "base": "home",
        "path": ".antigravity_tools",
        "expect": "Antigravity 的数据库与配置目录",
    },
    {
        "owner": "workbuddy",
        "base": "home",
        "path": ".workbuddy-key-fallback",
        "expect": "连接器密钥的回退存放目录",
        "credential": True,
    },
    {
        "owner": "workbuddy",
        "base": "home",
        "path": ".workbuddy",
        "expect": "WorkBuddy 主数据目录",
    },
    {
        "owner": "workbuddy",
        "base": "home",
        "path": "WorkBuddy",
        "expect": "疑似空壳残留目录",
    },
    {
        "owner": "workbuddy",
        "base": "roaming",
        "path": "WorkBuddy",
        "expect": "疑似空壳残留目录",
    },
    {
        "owner": "",
        "base": "drive",
        "path": "WorkBuddyStorage",
        "expect": "自定义存储目录的空壳残留（位于 E: 盘）",
        "drive": "E:",
    },
    {
        "owner": "",
        "base": "local",
        "path": "copilot",
        "expect": "疑似空壳残留目录",
    },
]

_BASE_RESOLVERS = {
    "home": home,
    "local": local_appdata,
    "roaming": roaming_appdata,
}


def _resolve_container(c: dict) -> Path | None:
    try:
        if c["base"] == "drive":
            drive = c.get("drive") or "E:"
            return Path(drive + os.sep) / c["path"]
        fn = _BASE_RESOLVERS.get(c["base"])
        if fn is None:
            return None
        return fn() / c["path"]
    except Exception:
        return None


# --------------------------------------------------------------------------
# Temporary directories
# --------------------------------------------------------------------------

#: Prefixes used by agent runtimes for their scratch directories. Matched
#: against the immediate children of %TEMP% only.
TEMP_PREFIXES = {
    "dsh": ("dsh-",),
    "workbuddy": ("workbuddy-", "wb-"),
    "codebuddy": ("codebuddy-", "cb-"),
    "copilot-chat": ("copilot-", "vscode-"),
    "antigravity": ("antigravity-",),
}


def temp_residue(agent_id: str, max_age_hours: float = 24.0) -> list[dict]:
    """Agent scratch directories under %TEMP%.

    A directory that is currently in use must not be reported as removable:
    several of these are live lock/socket holders. Age is used as the signal --
    a scratch dir untouched for a day is residue, a fresh one may be live.
    """
    prefixes = TEMP_PREFIXES.get(agent_id)
    if not prefixes:
        return []
    tmp = Path(os.environ.get("TEMP") or os.environ.get("TMP") or "C:/Windows/Temp")
    if not tmp.is_dir():
        return []
    now = time.time()
    out: list[dict] = []
    try:
        children = list(tmp.iterdir())
    except OSError:
        return []
    for p in children:
        name = p.name.lower()
        if not any(name.startswith(pre) for pre in prefixes):
            continue
        try:
            age_h = (now - p.stat().st_mtime) / 3600.0
        except OSError:
            continue
        size, files = _size_of(p)
        fresh = age_h < max_age_hours
        out.append(
            {
                "path": str(p),
                "size": size,
                "file_count": files,
                "age_hours": round(age_h, 1),
                "in_use": fresh,
                # A fresh scratch directory may be held open by a running
                # process, so it is surfaced for review rather than swept.
                "disposition": REVIEW if fresh else SAFE,
                "category": "temp",
                "evidence": (
                    f"%TEMP% 下以 “{name.split('-')[0]}-” 开头的临时目录，"
                    + ("最近 24 小时内仍被写入，可能正在使用" if fresh
                       else f"已 {age_h:.0f} 小时未变动")
                ),
            }
        )
    out.sort(key=lambda x: -x["size"])
    return out


def _size_of(p: Path) -> tuple[int, int]:
    if p.is_file():
        try:
            return p.stat().st_size, 1
        except OSError:
            return 0, 0
    from core.util import dir_size

    return dir_size(p)


# --------------------------------------------------------------------------
# Credentials
# --------------------------------------------------------------------------


def credential_residue(paths: list[Path]) -> list[dict]:
    """Key material found under the given paths.

    Reported separately and at higher visibility: sweeping a key file is both
    a cleanup and a security action, and the user should be told explicitly
    rather than have it disappear inside a bulk delete.
    """
    out: list[dict] = []
    seen: set[str] = set()
    for root in paths:
        if not root.exists():
            continue
        try:
            walker = root.rglob("*") if root.is_dir() else [root]
            for p in walker:
                if not p.is_file():
                    continue
                if not _is_key_file(p):
                    continue
                key = _norm(p)
                if key in seen:
                    continue
                seen.add(key)
                size, _n = _size_of(p)
                out.append(
                    {
                        "path": str(p),
                        "size": size,
                        "file_count": 1,
                        "disposition": REVIEW,
                        "category": "credential",
                        "evidence": f"文件名 “{p.name}” 符合密钥/凭据特征，卸载后仍会留存",
                    }
                )
        except (OSError, PermissionError):
            continue
    out.sort(key=lambda x: x["path"])
    return out


_KEY_SUFFIXES = (".key", ".pem", ".pfx", ".p12", ".jks", ".keystore", ".kdbx")

#: Words that suggest a credential, but only when they form a whole segment of
#: the name. Matching these as substrings produces a flood of false positives
#: from an agent's own bundled runtime -- "token-schema.json", "_tokenizer.py",
#: "token.py", "user-secret.svg", "Trust Tokens" are all part of a normal
#: installation and none of them holds a credential.
_KEY_WORDS = ("credential", "credentials", "token", "secret", "secrets",
              "apikey", "api-key", "keyblob", "private-key", "keyring")

#: A name segment that is a bare "key"/"keys" is only interesting when the file
#: also *looks* like key material (see _looks_like_key_material).
_KEY_SEGMENT_WORDS = _KEY_WORDS + ("key", "keys")

#: Extensions of files that are plainly source or data, never key material.
#: This is what removes `_tokenizer.py`, `token.cpython-313.pyc` and friends.
_NOT_KEY_SUFFIXES = (
    ".py", ".pyc", ".pyo", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".json", ".jsonl", ".md", ".txt", ".html", ".htm", ".css", ".svg",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf",
    ".map", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".lock", ".exe",
    ".dll", ".so", ".dylib", ".node", ".wasm", ".whl", ".zip", ".gz",
)

#: Content shapes that make a file plausibly a credential.
_KEY_CONTENT_MARKERS = (
    b"-----BEGIN", b"PRIVATE KEY", b"ssh-rsa", b"ssh-ed25519",
    b"AKIA", b"ASIA", b"sk-", b"ghp_", b"gho_", b"github_pat_",
    b"xoxb-", b"xoxp-", b"AIza",
)


def _segments(name: str) -> list[str]:
    return [s for s in re.split(r"[^a-z0-9]+", name.lower()) if s]


def _looks_like_key_material(p: Path) -> bool:
    """Whether an ambiguous file really holds key material.

    Reading the first 4 KiB is cheap and is the difference between reporting a
    real `.master.key` and reporting a bundled `token-schema.json`.
    """
    try:
        if p.stat().st_size > 4 * 1024 * 1024:
            return False
        with open(p, "rb") as fh:
            head = fh.read(4096)
    except OSError:
        return False
    return any(m in head for m in _KEY_CONTENT_MARKERS)


def _is_key_file(p: Path) -> bool:
    n = p.name.lower()

    # A private-key file extension is conclusive on its own.
    if n.endswith(_KEY_SUFFIXES):
        return True

    # Source / asset / document extensions are never key material, even when
    # the name contains "token" or "secret".
    if n.endswith(_NOT_KEY_SUFFIXES):
        return False

    segs = _segments(n)
    if not segs:
        return False
    # Require a *whole segment* to match, so "tokenizer" and "tokens" (as in
    # "Trust Tokens", a browser privacy feature) do not count.
    if not any(seg in _KEY_SEGMENT_WORDS for seg in segs):
        return False
    # An ambiguous name still has to look like key material inside.
    return _looks_like_key_material(p)


# --------------------------------------------------------------------------
# The scan
# --------------------------------------------------------------------------


class ResidueScanner:
    """Builds the residue report for one agent.

    Constructed with the live adapter so the report reflects what is installed
    *now*; the adapter may be absent (its storage survived a manual uninstall),
    in which case only the filesystem and Windows surfaces are reported.
    """

    def __init__(self, agent_id: str, adapter=None):
        self.agent_id = agent_id
        self.adapter = adapter
        self.label = getattr(adapter, "label", "") or agent_id
        self.clf = Classifier()

    # ---------------------------------------------------------------- helpers

    def _aliases(self) -> list[str]:
        """Extra names this product appears under, for matching."""
        out: list[str] = []
        if self.agent_id == "dsh":
            out += ["deepseek", "deepseek harness", "dsh"]
        if self.agent_id == "workbuddy":
            out += ["workbuddy", "work buddy", "genie"]
        if self.agent_id == "codebuddy":
            out += ["codebuddy", "code buddy"]
        if self.agent_id == "copilot-chat":
            out += ["copilot", "github copilot", "copilot chat"]
        if self.agent_id == "antigravity":
            out += ["antigravity", "lbjlaq"]
        return out

    def _install_paths(self) -> list[str]:
        out: list[str] = []
        try:
            for u in wininteg.uninstall_entries():
                if wininteg.match_entry([u], self.label, self._aliases()):
                    if u.get("install_location"):
                        out.append(u["install_location"])
                    if u.get("display_icon"):
                        out.append(u["display_icon"].strip('"'))
        except Exception:
            pass
        return out

    # ------------------------------------------------------------------ files

    def files(self) -> list[dict]:
        """Declared roots, known containers and everything actionable inside."""
        cands: list[Path] = []
        if self.adapter is not None:
            try:
                cands.extend(list(self.adapter.roots()))
            except Exception:
                pass
        for c in KNOWN_CONTAINERS:
            if c["owner"] and c["owner"] != self.agent_id:
                continue
            if not c["owner"] and self.agent_id != "":
                continue
            p = _resolve_container(c)
            if p is not None and p.exists():
                cands.append(p)

        deduped: list[Path] = []
        seen: set[str] = set()
        for p in cands:
            k = _norm(p)
            if k and k not in seen:
                seen.add(k)
                deduped.append(p)

        out: list[dict] = []
        for p in deduped:
            try:
                o = self.clf.classify(p)
            except Exception:
                continue
            out.append(o.to_dict())
            # Surface what is inside a root we are forbidden to remove as a
            # whole -- otherwise the 472 MB of browser cache under ~/.dsh would
            # never become visible.
            if p.is_dir():
                try:
                    for inner in drill_down(self.clf, [p], max_depth=3):
                        out.append(inner.to_dict())
                except Exception:
                    continue

        # De-duplicate the merged list, keeping the first (shallowest) verdict.
        merged: list[dict] = []
        seen2: set[str] = set()
        for d in out:
            k = _norm(d["path"])
            if k in seen2:
                continue
            seen2.add(k)
            merged.append(d)
        return merged

    # ------------------------------------------------------------- full scan

    def scan(self, include_windows: bool = True) -> dict:
        """The complete residue report."""
        started = time.time()
        files = self.files()
        creds: list[dict] = []
        for d in files:
            if d["category"] == "credential":
                creds.append(d)
        creds += credential_residue(
            [Path(d["path"]) for d in files if d["disposition"] != NEVER]
        )
        # Deduplicate credentials by path.
        seen: set[str] = set()
        uniq_creds = []
        for c in creds:
            k = _norm(c["path"])
            if k not in seen:
                seen.add(k)
                uniq_creds.append(c)

        tmp = temp_residue(self.agent_id)

        windows: dict = {}
        if include_windows:
            try:
                windows = wininteg.inventory_for(
                    self.label, self._aliases(), self._install_paths()
                )
            except Exception as e:
                windows = {
                    "error": f"{type(e).__name__}: {e}",
                    "counts": {},
                    "needs_admin": False,
                }

        summary = summarise(files, uniq_creds, tmp, windows)
        return {
            "agent": self.agent_id,
            "label": self.label,
            "installed": bool(getattr(self.adapter, "detect", lambda: False)()),
            "elapsed_ms": int((time.time() - started) * 1000),
            "files": files,
            "credentials": uniq_creds,
            "temp": tmp,
            "windows": windows,
            "summary": summary,
            "environment": wininteg.environment_summary(),
        }


def summarise(files: list[dict], creds: list[dict], tmp: list[dict],
              windows: dict) -> dict:
    from core.util import human_size

    def _sum(items, disp=None):
        return sum(i["size"] for i in items
                   if disp is None or i.get("disposition") == disp)

    counts = (windows or {}).get("counts", {}) or {}
    safe = [f for f in files if f["disposition"] == SAFE]
    review = [f for f in files if f["disposition"] == REVIEW]
    never = [f for f in files if f["disposition"] == NEVER]

    return {
        "safe_count": len(safe),
        "safe_bytes": _sum(safe),
        "safe_bytes_h": human_size(_sum(safe)),
        "review_count": len(review),
        "review_bytes": _sum(review),
        "review_bytes_h": human_size(_sum(review)),
        "never_count": len(never),
        "never_bytes": _sum(never),
        "never_bytes_h": human_size(_sum(never)),
        "credential_count": len(creds),
        "temp_count": len(tmp),
        "temp_bytes": sum(t["size"] for t in tmp),
        "temp_bytes_h": human_size(sum(t["size"] for t in tmp)),
        "reclaimable_bytes": _sum(safe) + sum(
            t["size"] for t in tmp if t["disposition"] == SAFE
        ),
        "reclaimable_bytes_h": human_size(
            _sum(safe) + sum(t["size"] for t in tmp if t["disposition"] == SAFE)
        ),
        "registry_keys": counts.get("registry_keys", 0),
        "removable_registry_keys": counts.get("removable_registry_keys", 0),
        "firewall_rules": counts.get("firewall", 0),
        "shortcuts": counts.get("shortcuts", 0),
        "orphan_shortcuts": counts.get("orphan_shortcuts", 0),
        "services": counts.get("services", 0),
        "scheduled_tasks": counts.get("scheduled_tasks", 0),
        "autostart": counts.get("autostart", 0),
        "needs_admin": bool((windows or {}).get("needs_admin")),
    }


def scan_agent(agent_id: str) -> dict:
    """Convenience wrapper used by the API and the CLI."""
    from adapters.registry import get_adapter

    return ResidueScanner(agent_id, get_adapter(agent_id)).scan()


def scan_all_agents() -> dict:
    """Residue for every adapter, plus the containers nobody claims."""
    from adapters.registry import all_adapters

    out: list[dict] = []
    for a in all_adapters():
        try:
            out.append(ResidueScanner(a.id, a).scan(include_windows=False))
        except Exception as e:
            out.append({"agent": a.id, "label": a.label,
                        "error": f"{type(e).__name__}: {e}", "summary": {}})

    # Containers with no owner: report them so they are not invisible, but never
    # as removable.
    orphans: list[dict] = []
    for c in KNOWN_CONTAINERS:
        if c["owner"]:
            continue
        p = _resolve_container(c)
        if p is None or not p.exists():
            continue
        o = Classifier().classify(p)
        d = o.to_dict()
        d["evidence"] = f"{d['evidence']}；{c['expect']}"
        d["disposition"] = REVIEW if d["disposition"] != NEVER else NEVER
        orphans.append(d)

    return {"agents": out, "unclaimed": orphans}
