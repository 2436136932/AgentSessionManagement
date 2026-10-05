"""Path ownership: which Agent does this path belong to, and how sure are we?

This is the missing piece that makes "clean up thoroughly" possible without
turning into "delete things by keyword match". A keyword scan on this very
machine hits `E:\\workbuddyapi-main` -- a user's own git repository that merely
*contains* a `.codebuddy` directory. Anything that deletes on a name match
would destroy it.

So instead of a boolean "is this ours", every path is classified on three
axes:

  * **owner**      which adapter id it belongs to ("" when unknown)
  * **confidence** how the ownership was established
                   ``exact``     derived from the registry, a package id, or an
                                 adapter's own declared root -- authoritative
                   ``heuristic`` matched a naming convention or a known vendor
                                 prefix -- plausible, needs a look
                   ``unknown``   we cannot say. Never auto-deleted, ever.
  * **category**   what kind of data it is, which is what decides whether
                   removing it is safe, needs review, or must never happen

The resulting **disposition** is what the UI and the executor actually act on:

  ``safe``    belongs to the agent, is reproducible or worthless (caches,
              logs, empty shells). Default-checked in the UI.
  ``review``  belongs to the agent but holds something a person may want
              (sessions, config, plugins, binaries). Shown, not default-checked.
  ``never``   user data, shared runtimes, source repositories, or anything we
              cannot attribute. Read-only in the UI; the executor refuses it.

Nothing in this module deletes anything. It only classifies, and it always
explains itself: each verdict carries an ``evidence`` string a user can check.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from core.util import home, local_appdata, norm, program_data, roaming_appdata

# --------------------------------------------------------------------------
# Dispositions
# --------------------------------------------------------------------------

SAFE = "safe"
REVIEW = "review"
NEVER = "never"

DISPOSITIONS = (SAFE, REVIEW, NEVER)

DISPOSITION_LABELS = {
    SAFE: "可安全清理",
    REVIEW: "需人工确认",
    NEVER: "禁止删除",
}

#: Categories, and the disposition each one gets when ownership is certain.
#: A heuristic match is downgraded by one step (safe -> review, review -> review)
#: because a naming convention is not proof.
CATEGORY_DISPOSITION = {
    "cache": SAFE,
    "log": SAFE,
    "temp": SAFE,
    "empty_shell": SAFE,
    "crash": SAFE,
    "credential": REVIEW,
    "session": REVIEW,
    "config": REVIEW,
    "plugin": REVIEW,
    "binary": REVIEW,
    "install": REVIEW,
    # A shortcut is only ever `review`: this classifier cannot see what a .lnk
    # points at, and a shortcut to a live program is not residue. The plan layer
    # checks the real target and upgrades a genuinely orphaned one to `safe`.
    "shortcut": REVIEW,
    "user_data": NEVER,
    "shared": NEVER,
    "source_repo": NEVER,
    "unknown": NEVER,
}

CATEGORY_LABELS = {
    "cache": "可再生缓存",
    "log": "日志",
    "temp": "临时文件",
    "empty_shell": "空壳目录",
    "crash": "崩溃转储",
    "credential": "密钥/凭据",
    "session": "会话记录",
    "config": "配置",
    "plugin": "插件/扩展",
    "binary": "内置二进制",
    "install": "安装目录",
    "shortcut": "快捷方式",
    "user_data": "用户数据",
    "shared": "共享资源",
    "source_repo": "源码仓库",
    "unknown": "无法确认",
}

# --------------------------------------------------------------------------
# Directory names that are pure cache, anywhere in a tree
# --------------------------------------------------------------------------
# Measured on this machine: top-level caches account for well under 1 MB, while
# *nested* caches (inside an Electron profile, a WebView2 user-data folder or a
# bundled browser) account for hundreds of MB. So the cache rule must be
# recursive -- but a nested match is only ever `review`, because a directory
# called "Cache" inside an application bundle is not always disposable.

#: Names that are pure render/compute caches. Regenerated on next launch, and
#: losing them costs at most a slower first paint. ONLY these are `safe`.
PURE_CACHE_DIR_NAMES = {
    "cache", "caches", "code cache", "gpucache", "gpu cache",
    "dawngraphitecache", "dawnwebgpucache", "shadercache", "grshadercache",
    "gpupersistentcache", "cacheddata", "component_crx_cache",
    "extensions_crx_cache", "crashpad", "browsermetrics",
    "browsermetrics-spare.pma", "shader_cache", "gr_shader_cache",
    "dawncache", "v8cache", "httpcache", "media cache",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
}

#: Browser/Electron storage that *looks* like cache but holds real state:
#: login sessions, IndexedDB of the app, service-worker registrations, offline
#: data. Deleting these logs the user out or loses app state, so they are
#: `review`, never auto-checked. This split matters: "Local Storage" next to
#: "GPUCache" would otherwise both be swept by a naive cache rule.
STATEFUL_STORE_DIR_NAMES = {
    "local storage", "session storage", "indexeddb", "cachestorage",
    "service worker", "websql", "shared dictionary", "dictionaries",
    "segmentation platform", "blob_storage", "file system",
    "extension state", "sync data", "syncdata",
}

#: Kept for backwards compatibility with earlier callers/tests.
CACHE_DIR_NAMES = PURE_CACHE_DIR_NAMES | STATEFUL_STORE_DIR_NAMES

LOG_DIR_NAMES = {"logs", "log", "diagnostics", "crashpad", "crashdumps", "reports"}

TEMP_DIR_NAMES = {"tmp", "temp", "incomplete", "downloads-tmp", "pending-telemetry"}

#: Vendor-scoped container names seen in the wild: ``@scope-app`` (Electron
#: user-data) and ``com.vendor.app`` (reverse-DNS app id). These are strong
#: hints that the directory was created by a packaged desktop app -- but only
#: when they are *directories* and only when the first label is a real
#: top-level domain. Without the TLD check, an ordinary filename containing a
#: dot ("state.vscdb") falsely reads as a reverse-DNS bundle id.
_VENDOR_SCOPED = re.compile(r"^@[a-z0-9][a-z0-9._-]*$", re.I)
_TLDS = (
    "com", "org", "net", "io", "dev", "app", "ai", "co", "cn", "uk", "de",
    "fr", "jp", "ru", "us", "info", "biz", "me", "sh", "xyz", "top", "site",
)
_REVERSE_DNS = re.compile(
    r"^(?:" + "|".join(_TLDS) + r")(\.[a-z0-9][a-z0-9_-]*){1,4}$", re.I
)

# --------------------------------------------------------------------------
# Never-touch rules. These are checked FIRST and, when they hit, nothing else
# in this module can override the verdict.
# --------------------------------------------------------------------------

#: Directories that are never a single agent's private property. Deleting these
#: breaks unrelated software: HKCU\SOFTWARE\Tencent is shared with QQ and
#: WeChat, and a VC++ redistributable is used by everything on the machine.
SHARED_CONTAINERS = {
    "microsoft", "windows", "tencent", "google", "mozilla", "apple",
    "nvidia", "intel", "amd", "realtek", "adobe", "oracle", "java",
    "python", "nodejs", "git", "docker", "wsl", "packages",
    "microsoft.net", "dotnet", "common files", "windowsapps",
    "program files", "program files (x86)", "programdata",
}

#: Signals that a directory is a source checkout. A git repository is someone's
#: work, even when it contains an agent's dot-folder. This is the rule that
#: protects `E:\\workbuddyapi-main`.
SOURCE_REPO_MARKERS = (".git", ".hg", ".svn", "package.json", "pyproject.toml",
                       "cargo.toml", "go.mod", "pom.xml", "build.gradle")

#: File extensions that carry secrets.
CREDENTIAL_SUFFIXES = (".key", ".pem", ".pfx", ".p12", ".jks", ".keystore", ".kdbx")

#: Extensions of compiled / interpreted code. These are never a credential
#: store, and the veto is absolute: "git-credential-helper-selector.exe" is a
#: helper binary whose *name* mentions credentials, not a key file.
NEVER_CREDENTIAL_SUFFIXES = (
    ".exe", ".dll", ".so", ".dylib", ".node", ".wasm", ".sys", ".msi",
    ".py", ".pyc", ".pyo", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".class", ".jar", ".bin", ".dat", ".pak", ".asar",
)

#: Extensions of documents and assets. These are usually not key material, but
#: a *strong* name match still wins: `~/.dsh/.credentials.yaml` is a real
#: credential store despite the `.yaml` extension.
SOFT_NOT_CREDENTIAL_SUFFIXES = (
    ".json", ".jsonl", ".md", ".txt", ".html", ".htm", ".css", ".svg",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf",
    ".map", ".yml", ".yaml", ".toml", ".ini", ".cfg",
)


#: Names of browser/Chromium subsystems that contain "token" or "secret" but
#: hold no credentials at all. Without this exclusion, every Chromium profile
#: on the machine reports a fistful of phantom "credential" findings and the
#: real key files drown in the noise.
NOT_CREDENTIAL_NAMES = {
    "trust tokens", "trust tokens-journal", "trusttokenkeycommitments",
    "vpn tokens", "vpn tokens-journal", "private state tokens",
    "private state tokens-journal", "trust token key commitments",
    "tokenized-card", "wallet-tokenization-config", "token-schema.json",
}


def _looks_like_credential(p: Path) -> bool:
    n = p.name.lower()

    # 0. Known Chromium/browser subsystems are never credentials.
    if n in NOT_CREDENTIAL_NAMES:
        return False

    # 1. A private-key extension is conclusive.
    if n.endswith(CREDENTIAL_SUFFIXES):
        return True

    # 2. Compiled/interpreted code is never a credential store, whatever its
    #    name says. Checked before the name rules so that a helper binary
    #    called "git-credential-helper-selector.exe" is not reported.
    if n.endswith(NEVER_CREDENTIAL_SUFFIXES):
        return False

    # 3. A strong name match wins over the soft document veto.
    stem = p.stem.lower()
    if any(h in stem for h in CREDENTIAL_FILE_HINTS):
        return True

    # 4. Documents and assets are not key material without a strong name match,
    #    which removes "token-schema.json", "user-secret.svg" and the like.
    if n.endswith(SOFT_NOT_CREDENTIAL_SUFFIXES):
        return False

    if p.is_dir() and _CRED_BOUNDARY.search(n):
        return True
    return False


def _norm(p) -> str:
    try:
        return os.path.normcase(os.path.normpath(str(Path(p).absolute())))
    except (OSError, ValueError):
        return ""


def is_source_repo(p: Path) -> bool:
    """True when `p` looks like a source checkout that must not be swept."""
    try:
        if p.is_file():
            p = p.parent
        for marker in SOURCE_REPO_MARKERS:
            if (p / marker).exists():
                return True
    except OSError:
        pass
    return False


#: Substrings that hint at key material in a *stem*. This list is deliberately
#: short: a long list of loose words ("token", "secret") matches an agent's own
#: bundled runtime and buries the real key files in noise.
CREDENTIAL_FILE_HINTS = ("credential", "credentials", "apikey", "api-key",
                         "private-key", "keyblob", "id_rsa", "id_ed25519",
                         "master.key", "session-key")

#: Whole directory names that hold key material.
CREDENTIAL_DIR_HINTS = ("credentials", "credential", "secrets", "secret",
                        "tokens", "token-store", "tokenstore", "keys",
                        "keyring", "key-fallback", "keyfallback", "keystore",
                        "keyblob", "auth-keys", "session-keys")

#: A hint only counts when it sits on a word boundary in the directory name.
#: "workbuddy-key-fallback" and "connector-keys" match; a browser component
#: named "TrustTokenKeyCommitments" does not, even though it contains "token"
#: and "key" as substrings.
_CRED_BOUNDARY = re.compile(
    r"(?<![a-z0-9])(?:" + "|".join(re.escape(h) for h in CREDENTIAL_DIR_HINTS) + r")(?![a-z0-9])"
)


def is_empty_shell(p: Path) -> tuple[bool, int]:
    """(is_it_an_empty_tree, file_count). Directories only."""
    n = 0
    try:
        if not p.is_dir():
            return False, 0
        for _dp, _dn, fns in os.walk(p, onerror=lambda e: None):
            n += len(fns)
            if n:
                return False, n
    except OSError:
        return False, 0
    return True, n


# --------------------------------------------------------------------------
# The classifier
# --------------------------------------------------------------------------


class Owned:
    """One classified path."""

    __slots__ = ("path", "owner", "owner_label", "confidence", "category",
                 "disposition", "evidence", "size", "file_count", "depth")

    def __init__(self, path, owner="", owner_label="", confidence="unknown",
                 category="unknown", disposition=NEVER, evidence="",
                 size=0, file_count=0, depth=0):
        self.path = str(path)
        self.owner = owner
        self.owner_label = owner_label
        self.confidence = confidence
        self.category = category
        self.disposition = disposition
        self.evidence = evidence
        self.size = size
        self.file_count = file_count
        self.depth = depth

    def to_dict(self) -> dict:
        from core.util import human_size

        return {
            "path": self.path,
            "owner": self.owner,
            "owner_label": self.owner_label,
            "confidence": self.confidence,
            "category": self.category,
            "category_label": CATEGORY_LABELS.get(self.category, self.category),
            "disposition": self.disposition,
            "disposition_label": DISPOSITION_LABELS.get(self.disposition, ""),
            "evidence": self.evidence,
            "size": self.size,
            "size_h": human_size(self.size),
            "file_count": self.file_count,
            "depth": self.depth,
            "checkable": self.disposition == SAFE,
        }


def _downgrade(disposition: str) -> str:
    """A heuristic match can never be more permissive than `review`."""
    return REVIEW if disposition == SAFE else disposition


def _shared_hit(parts: tuple[str, ...]) -> str:
    """The shared container this path lives in, or ''.

    Only the first two components *below the drive anchor* are considered.
    The intent of this rule is "do not delete a shared install root such as
    `C:\\Program Files` or `C:\\Windows`", and those are decided at the top of
    the tree. Scanning every component instead produces false refusals deep in
    user-owned paths: `%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs`
    contains both "Microsoft" and "Windows", which made every Start Menu
    shortcut look like a shared system resource and therefore undeletable.
    """
    # parts looks like ('C:\\', 'Users', 'admin', 'AppData', ...) on Windows.
    if not parts:
        return ""
    tail = [p for p in parts[1:] if p not in ("\\", "/")]
    for part in tail[:2]:
        if part.lower() in SHARED_CONTAINERS:
            return part
    return ""


class Classifier:
    """Classifies paths against the agents actually installed here.

    Built from live adapters so the rules follow the machine rather than a
    hard-coded list: an adapter's declared roots are `exact` ownership, and the
    vendor prefixes derived from them feed the heuristic pass.
    """

    def __init__(self, adapters=None):
        if adapters is None:
            from adapters.registry import all_adapters

            adapters = [a for a in all_adapters() if _safe_detect(a)]
        self.adapters = adapters
        # exact roots, longest first so the most specific wins
        self._roots: list[tuple[str, object]] = []
        for a in adapters:
            for r in _safe_roots(a):
                self._roots.append((_norm(r), a))
        self._roots.sort(key=lambda x: -len(x[0]))
        #: Bare set of declared root paths, for the "never promote to safe"
        #: backstop in classify().
        self._root_keys: set[str] = {k for k, _a in self._roots}

        # Heuristic tokens: an adapter label's first word, plus the dot-folder
        # and vendor-scoped names that its roots imply.
        self._tokens: list[tuple[str, object]] = []
        for a in adapters:
            toks = set()
            for w in str(a.label).lower().split():
                if len(w) > 3:
                    toks.add(w)
            toks.add(str(a.id).lower().replace("-", ""))
            toks.add(str(a.id).lower().replace("-", " "))
            for r in _safe_roots(a):
                for part in Path(r).parts:
                    low = part.lower()
                    if low.startswith(".") and len(low) > 3:
                        toks.add(low.lstrip("."))
                    if low.startswith("@"):
                        toks.add(low)
            for t in toks:
                if t:
                    self._tokens.append((t, a))
        self._tokens.sort(key=lambda x: -len(x[0]))

    # ------------------------------------------------------------------ match

    def owner_of(self, p) -> tuple[object | None, str, str]:
        """(adapter | None, confidence, evidence)."""
        target = _norm(p)
        if not target:
            return None, "unknown", "路径无法解析"
        for root, a in self._roots:
            if target == root or target.startswith(root + os.sep):
                return a, "exact", f"位于 {a.label} 声明的数据根目录内"
        name = Path(target).name.lower()
        for tok, a in self._tokens:
            if tok and (tok in name):
                return a, "heuristic", f"目录名包含 “{tok}”，与 {a.label} 相关"
        return None, "unknown", "没有匹配到任何已安装 Agent 的特征"

    # ------------------------------------------------------------- categorize

    def categorize(self, p: Path, owner_confidence: str,
                   subtree: tuple[int, int] | None = None) -> tuple[str, str]:
        """(category, evidence). `p` is the path itself.

        `subtree` is the precomputed ``(bytes, files)`` for a directory, used to
        recognise an empty shell without another walk.
        """
        name = p.name.lower()
        parts = tuple(p.parts)

        # --- absolute vetoes, checked before anything else ------------------
        shared = _shared_hit(parts)
        if shared:
            return "shared", f"位于共享容器 “{shared}” 之下，删除会影响其他软件"

        if p.is_dir() and is_source_repo(p):
            return "source_repo", "含源码仓库特征文件（.git / package.json / pyproject.toml 等），属于用户自己的工程"

        if _looks_like_credential(p):
            return "credential", "文件名或目录名符合密钥/凭据特征"

        # --- empty shells ---------------------------------------------------
        # Checked early and with the precomputed size, because "directory exists
        # but holds nothing" is the single most common uninstall leftover and
        # the cheapest thing to reclaim.
        if p.is_dir():
            if subtree is not None:
                if subtree[1] == 0:
                    return "empty_shell", "目录存在但递归没有任何文件"
            else:
                empty, _n = is_empty_shell(p)
                if empty:
                    return "empty_shell", "目录存在但递归没有任何文件"

        # --- ordinary categories -------------------------------------------
        # Order matters. A path that an adapter loudly claims as its data root
        # must never be downgraded to "cache" by a name rule, so the name rules
        # that only *look* like cache are checked with the ownership context.
        if name in PURE_CACHE_DIR_NAMES:
            return "cache", f"目录名 “{p.name}” 是可再生缓存"
        if name in STATEFUL_STORE_DIR_NAMES:
            return "user_data", f"目录名 “{p.name}” 保存应用状态（删除会丢失登录态或离线数据）"
        if name in LOG_DIR_NAMES:
            return "log", f"目录名 “{p.name}” 是日志目录"
        if name in TEMP_DIR_NAMES:
            return "temp", f"目录名 “{p.name}” 是临时目录"

        if p.is_file():
            if p.suffix.lower() in (".log", ".dmp", ".etl"):
                return "log", f"扩展名 {p.suffix} 属于日志文件"
            if p.suffix.lower() == ".tmp":
                return "temp", f"扩展名 {p.suffix} 属于临时文件"
            # A Windows shortcut is a small file that can be moved into the
            # quarantine and restored, so it is actionable residue -- but this
            # classifier cannot read its target, so it stays `review`.
            if p.suffix.lower() == ".lnk":
                return "shortcut", f"文件名 “{p.name}” 是 Windows 快捷方式"
            if p.suffix.lower() in (".url",):
                return "shortcut", f"文件名 “{p.name}” 是 Internet 快捷方式"
            # A SQLite sidecar carries the same weight as its database: the
            # WAL holds committed transactions and the journal holds an
            # in-flight rollback. Sweeping them corrupts the store, so they are
            # always user data, never cache.
            if p.suffix.lower() in (".vscdb", ".db", ".sqlite", ".sqlite3"):
                return "user_data", f"文件名 “{p.name}” 是数据库，内含应用状态"
            if p.name.lower().endswith((".db-wal", ".db-shm", ".db-journal",
                                        ".sqlite-wal", ".sqlite-shm",
                                        "-wal", "-shm", "-journal")):
                return "user_data", f"文件名 “{p.name}” 是数据库的预写日志，删除会损坏数据"

        low = name
        if low in ("plugins", "extensions", "skills", "skill-cloud-sync"):
            return "plugin", f"目录名 “{p.name}” 存放插件或扩展"
        if low in ("binaries", "bin", "runtime", "node_modules", "vendor"):
            return "binary", f"目录名 “{p.name}” 存放可执行文件或依赖"
        if low in ("sessions", "session", "conversations", "history", "chats",
                   "dsh-session-archive", "transcripts"):
            return "session", f"目录名 “{p.name}” 存放会话记录"
        if low in ("audit-log", "logs"):
            return "log", f"目录名 “{p.name}” 是日志目录"
        if low in ("profiles", "profile", "storages", "storage", "memory",
                   "local_storage", "app", "security", "connectors"):
            return "user_data", f"目录名 “{p.name}” 存放应用状态"

        if name in ("settings.json", "config.json", "preferences.json",
                    "gui_config.json", "mcp.json", "mcp-tool-list.json"):
            return "config", f"文件名 “{p.name}” 是配置文件"

        # Only now consider the packaged-app naming heuristics, and only for
        # directories. A file with dots in its name is not a bundle id.
        if p.is_dir() and (_VENDOR_SCOPED.match(p.name) or _REVERSE_DNS.match(p.name)):
            if owner_confidence == "exact":
                # An adapter declares this as its own root: it is application
                # data, not a disposable cache.
                return "user_data", "该 Agent 自己声明的数据容器"
            return "cache", f"目录名 “{p.name}” 是打包应用的私有数据容器（通常是缓存）"

        if owner_confidence == "exact":
            return "user_data", "位于该 Agent 的数据根目录内"
        return "unknown", "无法判断这是什么类型的数据"

    # -------------------------------------------------------------- classify

    def classify(self, p, depth: int = 0, measure: bool = True,
                 subtree: tuple[int, int] | None = None) -> Owned:
        """Classify one path.

        `subtree` is an optional precomputed ``(bytes, files)`` for a directory.
        Passing it avoids re-walking the tree, which matters because the drill
        down classifies every node of an agent's root: measuring each one
        independently would be quadratic (17k files under ~/.dsh).
        """
        path = Path(p)
        adapter, confidence, evidence = self.owner_of(path)
        category, cat_evidence = self.categorize(path, confidence, subtree)

        disp = CATEGORY_DISPOSITION.get(category, NEVER)
        if confidence == "heuristic":
            disp = _downgrade(disp)
        # "We do not know what this is" has two very different cases:
        #   * heuristic owner  -- we are fairly sure *whose* it is, just not
        #     what is inside. That is precisely a `review`: show it during an
        #     uninstall, let a person decide. Hiding it would recreate the very
        #     blind spot this tool exists to fix.
        #   * unknown owner    -- we cannot even say whose it is. Never touch.
        if category == "unknown":
            disp = REVIEW if confidence == "heuristic" else NEVER

        # An empty directory is the one case where ownership confidence does not
        # matter: it holds no files, so removing it cannot lose data, and it is
        # the single most common uninstall leftover. Stays visible and
        # removable even when we cannot attribute it.
        if category == "empty_shell":
            disp = SAFE
        # A shared/source verdict is final regardless of how sure we are about
        # the owner. (An *unattributed* path is handled above.)
        if category in ("shared", "source_repo"):
            disp = NEVER
        # Two categories must stay visible even when we cannot name the owner:
        # a stray key directory is exactly what a manual cleanup misses. It is
        # surfaced as `review`, never auto-checked, since an unattributed path is
        # not ours to remove. (An empty shell is handled above as `safe`.)
        if category == "credential" and confidence == "unknown":
            disp = REVIEW

        # Hard backstop: a path an adapter declares as one of its own roots is
        # application data by definition. No name-based rule may ever promote it
        # to `safe`. This is what stops "the folder is called CodeBuddyExtension"
        # from becoming "delete the adapter's own storage".
        if confidence == "exact" and _norm(path) in self._root_keys:
            disp = REVIEW if disp == SAFE else disp
            cat_evidence = cat_evidence or "该路径是 Agent 自己声明的数据根目录"

        size = files = 0
        if subtree is not None:
            size, files = subtree
        elif measure:
            from core.util import dir_size

            try:
                if path.is_dir():
                    size, files = dir_size(path)
                elif path.is_file():
                    size, files = path.stat().st_size, 1
            except OSError:
                pass

        return Owned(
            path=path,
            owner=(adapter.id if adapter else ""),
            owner_label=(adapter.label if adapter else ""),
            confidence=confidence,
            category=category,
            disposition=disp,
            evidence="；".join(x for x in (evidence, cat_evidence) if x),
            size=size,
            file_count=files,
            depth=depth,
        )


def _safe_detect(a) -> bool:
    try:
        return bool(a.detect())
    except Exception:
        return False


def _safe_roots(a) -> list[Path]:
    try:
        return list(a.roots())
    except Exception:
        return []


# --------------------------------------------------------------------------
# Candidate discovery for the residue scan
# --------------------------------------------------------------------------

def _iter_candidates():
    """Places worth looking at. Discovery only -- classification decides."""
    homes = [home(), roaming_appdata(), local_appdata(), program_data()]
    for base in homes:
        try:
            for child in base.iterdir():
                if child.name.startswith(".") or True:
                    yield child
        except OSError:
            continue
    # The traditional Electron / WebView2 user-data roots sit one level deeper.
    for sub in ("Programs", "Packages"):
        for base in (local_appdata(),):
            p = base / sub
            try:
                for child in p.iterdir():
                    yield child
            except OSError:
                continue
    # Per-user Start Menu shortcuts are handled by core.integration, not here.


def scan_disk(limit: int = 4000) -> list[Owned]:
    """Classify top-level entries of the user's own data roots.

    Deliberately shallow: this walks the *containers* (home, Roaming, Local,
    ProgramData), never a whole drive. Anything that resolves to `unknown` is
    reported as such rather than guessed at.
    """
    out: list[Owned] = []
    clf = Classifier()
    seen: set[str] = set()
    for cand in _iter_candidates():
        if len(out) >= limit:
            break
        key = _norm(cand)
        if not key or key in seen:
            continue
        seen.add(key)
        try:
            o = clf.classify(cand, depth=0)
        except Exception:
            continue
        # Only report things we can attribute, plus empty shells (which are
        # worth reporting even when unattributable, but never auto-removable).
        if o.confidence == "unknown" and o.category != "empty_shell":
            continue
        out.append(o)
    out.sort(key=lambda x: (x.disposition != SAFE, -x.size))
    return out


# --------------------------------------------------------------------------
# Recursive drill down
# --------------------------------------------------------------------------
# A top-level verdict of `never` is correct but unhelpful: `~/.dsh` as a whole
# must never be deleted, yet 472 MB of browser component cache and a stray key
# directory live *inside* it. So after classifying a root, walk into it and
# surface the nodes that are individually actionable.
#
# The walk is single-pass and bottom-up: sizes are computed once per node while
# descending, so classifying a 17k-file tree stays linear. Subtrees that are
# `shared` or `source_repo` are never entered -- those are the absolute vetoes,
# and there is nothing inside them we are allowed to touch anyway.

#: Directories that never contain an actionable item and are expensive to walk.
_DRILL_SKIP = {"node_modules", ".git", ".svn", ".hg", "winsxs"}

#: Hard cap on nodes visited, so a pathological tree cannot hang the UI.
_DRILL_NODE_CAP = 60000


def _measure_subtree(root: Path) -> dict[str, tuple[int, int]]:
    """One pass over `root`: {normalised path -> (bytes, files)} for every dir.

    Files are attributed to their parent directory. Returns sizes bottom-up.
    """
    sizes: dict[str, tuple[int, int]] = {}
    try:
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
            b = 0
            for fn in filenames:
                try:
                    b += os.stat(os.path.join(dirpath, fn)).st_size
                except OSError:
                    continue
            sizes[_norm(dirpath)] = (b, len(filenames))
            for d in list(dirnames):
                if d.lower() in _DRILL_SKIP:
                    dirnames.remove(d)
    except OSError:
        pass

    # Roll child totals into parents (deepest first).
    for dp in sorted(sizes, key=lambda s: -s.count(os.sep)):
        parent = _norm(Path(dp).parent)
        if parent in sizes and parent != dp:
            pb, pf = sizes[parent]
            cb, cf = sizes[dp]
            sizes[parent] = (pb + cb, pf + cf)
    return sizes


def drill_down(clf: "Classifier", roots: list[Path], max_depth: int = 3,
               min_size: int = 64 * 1024) -> list[Owned]:
    """Classify the actionable nodes inside each root.

    Returns only nodes whose disposition is not `never`, or that are
    `empty_shell`/`credential` (which are worth surfacing even when the owner is
    uncertain). Nodes smaller than `min_size` are dropped unless they are an
    empty shell or a credential -- those matter regardless of size.
    """
    out: list[Owned] = []
    visited = 0
    seen: set[str] = set()

    for root in roots:
        if not root.exists() or not root.is_dir():
            continue
        sizes = _measure_subtree(root)
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
            rel = Path(dirpath)
            try:
                depth = len(rel.relative_to(root).parts)
            except ValueError:
                depth = 0
            if depth >= max_depth:
                dirnames[:] = []

            entries = [rel / d for d in dirnames] + [rel / f for f in filenames]
            for ent in entries:
                visited += 1
                if visited > _DRILL_NODE_CAP:
                    return out
                key = _norm(ent)
                if key in seen:
                    continue
                seen.add(key)
                try:
                    sub = sizes.get(key) if ent.is_dir() else None
                    o = clf.classify(ent, depth=depth + 1, subtree=sub)
                except Exception:
                    continue
                if o.category in ("shared", "source_repo"):
                    # Absolute veto: do not descend. Pruning here is what keeps
                    # a source checkout or a shared runtime entirely untouched.
                    if ent.is_dir() and ent.name in dirnames:
                        dirnames.remove(ent.name)
                    continue
                interesting = (
                    o.disposition != NEVER
                    or o.category in ("empty_shell", "credential")
                )
                if not interesting:
                    continue
                if o.size < min_size and o.category not in ("empty_shell", "credential"):
                    continue
                out.append(o)

    out.sort(key=lambda x: (x.disposition != SAFE, -x.size))
    return out


def scan_all(max_depth: int = 3) -> dict:
    """The full picture: roots plus the actionable nodes inside them."""
    clf = Classifier()
    roots: list[Path] = []
    for a in clf.adapters:
        roots.extend(_safe_roots(a))
    # Plus the vendor-scoped containers that no adapter declares yet.
    for base, name in (
        (roaming_appdata(), "@deepseek-ai"),
        (local_appdata(), "com.lbjlaq.antigravity-tools"),
        (local_appdata(), "CodeBuddyExtension"),
        (local_appdata(), "copilot"),
        (home(), ".workbuddy-key-fallback"),
        (home(), "WorkBuddy"),
        (roaming_appdata(), "WorkBuddy"),
    ):
        p = base / name
        if p.exists():
            roots.append(p)

    deduped: list[Path] = []
    seen: set[str] = set()
    for r in roots:
        k = _norm(r)
        if k and k not in seen:
            seen.add(k)
            deduped.append(r)

    top = [clf.classify(r) for r in deduped]
    nested = drill_down(clf, deduped, max_depth=max_depth)
    # A nested node that is the same path as a root is redundant.
    top_keys = {_norm(o.path) for o in top}
    nested = [o for o in nested if _norm(o.path) not in top_keys]

    return {
        "roots": [o.to_dict() for o in top],
        "items": [o.to_dict() for o in nested],
        "summary": summarize(top + nested),
    }


def summarize(items: list[Owned]) -> dict:
    agg = {SAFE: [0, 0], REVIEW: [0, 0], NEVER: [0, 0]}
    for it in items:
        agg[it.disposition][0] += it.size
        agg[it.disposition][1] += 1
    from core.util import human_size

    return {
        "total": len(items),
        "safe_count": agg[SAFE][1],
        "safe_bytes": agg[SAFE][0],
        "safe_bytes_h": human_size(agg[SAFE][0]),
        "review_count": agg[REVIEW][1],
        "review_bytes": agg[REVIEW][0],
        "review_bytes_h": human_size(agg[REVIEW][0]),
        "never_count": agg[NEVER][1],
        "never_bytes": agg[NEVER][0],
        "never_bytes_h": human_size(agg[NEVER][0]),
        "by_disposition": {k: {"count": v[1], "bytes": v[0]} for k, v in agg.items()},
    }
