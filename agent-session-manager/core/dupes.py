"""Duplicate finder: report content that is stored twice, wasting disk space.

This module is **strictly READ-ONLY**. It walks, stats and hashes files; it
never deletes, moves, renames or rewrites anything, and it holds no reference
to the executor. 本模块只读：不会删除、移动或修改任何文件。是否删除完全由人工
复核后交给执行器（core.executor）决定，本模块只给出证据。

The intended use is the residue that agent storage accumulates on its own:
the same transcript copied into two workspaces, the same attachment blob
uploaded twice under different ids. Those are the cases where deleting one copy
is usually harmless -- but only a human can decide that, which is why this
module stops at reporting.

Cost control (a real machine has ~30k files):

  * only files at or above `min_bytes` are considered;
  * files are grouped by exact size and any size with a single member is
    dropped before a single byte is read -- this is the main speed win, since
    most files are unique in size and cost nothing but a stat();
  * survivors are compared on their first 64 KiB, and only files whose prefixes
    already match are read in full to confirm.

Files inside a source checkout (any ancestor up to the adapter root containing
a `.git` directory) are skipped: two identical files in a repository are
checked-in content, not waste, and proposing them for deletion would be wrong.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from adapters.registry import all_adapters
from core.util import human_size, is_within, ms_to_iso, norm

#: Only compare the leading N bytes before falling back to a full read.
PREFIX_BYTES = 64 * 1024

#: Files at or above this size are skipped: hashing them is too expensive for
#: the value of the finding, and files this large are rarely duplicates.
MAX_FILE_BYTES = 512 * 1024 * 1024

#: At most this many result groups are returned.
MAX_GROUPS = 500

#: Read buffer for hashing.
_CHUNK = 1024 * 1024


# --------------------------------------------------------------------------
# Hashing
# --------------------------------------------------------------------------


def _hash_file(path: str, limit: int | None = None) -> str | None:
    """BLAKE2b hex digest of a file, or None when it cannot be read.

    `limit` restricts the read to the leading bytes, which is what makes the
    first comparison pass cheap on large transcripts.
    """
    h = hashlib.blake2b(digest_size=32)
    try:
        with open(path, "rb") as fh:
            remaining = limit
            while True:
                want = _CHUNK if remaining is None else min(_CHUNK, remaining)
                if want <= 0:
                    break
                chunk = fh.read(want)
                if not chunk:
                    break
                h.update(chunk)
                if remaining is not None:
                    remaining -= len(chunk)
    except OSError:
        return None
    return h.hexdigest()


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------

_ATTACHMENT_TOKENS = ("attachment", "attachments")
_SESSION_TOKENS = ("session", "conversation", "history", "transcripts")


def classify(path: str) -> str:
    """Kind of storage a path belongs to: session, attachment or other."""
    low = (path or "").lower()
    if any(t in low for t in _ATTACHMENT_TOKENS):
        return "attachment"
    if any(t in low for t in _SESSION_TOKENS):
        return "session"
    return "other"


# --------------------------------------------------------------------------
# Source-checkout guard
# --------------------------------------------------------------------------


def _in_checkout(dirpath: str, root_key: str, memo: dict[str, bool]) -> bool:
    """True when `dirpath` or an ancestor up to the adapter root holds `.git`.

    The walk stops at the adapter root: a `.git` in an unrelated ancestor (for
    instance the whole drive being a repository) must not swallow the scan.

    Containment is a prefix test on already-normalised path strings rather than
    a call to `is_within()`. That is the same comparison `is_within()` makes,
    but without `Path.resolve()`: resolving once per directory level cost
    ~48k `_getfinalpathname` syscalls (~2.7 s) on a real machine, which is
    pure overhead here because os.walk() already yields paths under the root.
    Every directory is visited at most once thanks to `memo`.
    """
    key = os.path.normcase(os.path.normpath(dirpath))
    prefix = root_key + os.sep
    pending: list[str] = []
    flag = False

    cur = key
    while True:
        if cur != root_key and not cur.startswith(prefix):
            break  # stepped outside the adapter root: look no further
        cached = memo.get(cur)
        if cached is not None:
            flag = cached
            break
        try:
            if os.path.isdir(os.path.join(cur, ".git")):
                flag = True
                break
        except OSError:
            pass
        pending.append(cur)
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent

    for p in pending:
        memo[p] = flag
    return flag


# --------------------------------------------------------------------------
# Scan
# --------------------------------------------------------------------------


def _roots() -> list[tuple[str, Path]]:
    """(agent_id, root) for every existing root of every installed adapter."""
    out: list[tuple[str, Path]] = []
    for a in all_adapters():
        try:
            if not a.detect():
                continue
            roots = a.existing_roots()
        except Exception:
            continue
        for r in roots or []:
            try:
                out.append((str(a.id), Path(r)))
            except (TypeError, ValueError):
                continue
    return out


def _collect(min_bytes: int, limit: int) -> tuple[list[dict], int, int, bool]:
    """Walk the roots and return (candidates, scanned, errors, truncated).

    Only metadata is touched here -- no file content is read in this phase.
    """
    candidates: list[dict] = []
    seen: set[str] = set()
    scanned = 0
    errors = 0
    truncated = False

    for agent, root in _roots():
        if truncated:
            break
        memo: dict[str, bool] = {}
        try:
            root_key = norm(root)
        except (OSError, ValueError):
            errors += 1
            continue
        try:
            walker = os.walk(root, onerror=lambda e: None)
            for dirpath, dirnames, filenames in walker:
                try:
                    if _in_checkout(dirpath, root_key, memo):
                        # A whole checkout is skipped, subtree included.
                        dirnames[:] = []
                        continue
                except OSError:
                    errors += 1
                    continue
                for fn in filenames:
                    scanned += 1
                    full = os.path.join(dirpath, fn)
                    try:
                        st = os.stat(full)
                    except OSError:
                        errors += 1
                        continue
                    size = int(st.st_size)
                    if size == 0 or size < min_bytes or size > MAX_FILE_BYTES:
                        continue
                    try:
                        key = norm(full)
                    except (OSError, ValueError):
                        errors += 1
                        continue
                    if key in seen:
                        # Reachable through two roots: count it once.
                        continue
                    seen.add(key)
                    candidates.append(
                        {
                            "path": str(full),
                            "agent": agent,
                            "size": size,
                            "mtime": int(st.st_mtime * 1000),
                            # Kept for the containment check applied to the
                            # paths that are actually reported (see _group).
                            "root": root,
                        }
                    )
                    if len(candidates) >= limit:
                        truncated = True
                        break
                if truncated:
                    break
        except OSError:
            errors += 1
            continue

    return candidates, scanned, errors, truncated


def _kind_for(items: list[dict]) -> str:
    """The dominant kind of a group (a group can span session and attachment)."""
    counts: dict[str, int] = {}
    for c in items:
        k = classify(c["path"])
        counts[k] = counts.get(k, 0) + 1
    if not counts:
        return "other"
    # Ties resolve to the fixed precedence of classify()'s own ordering.
    order = {"attachment": 0, "session": 1, "other": 2}
    return min(counts.items(), key=lambda kv: (-kv[1], order.get(kv[0], 9)))[0]


def _contained(items: list[dict]) -> list[dict]:
    """Drop members that no longer resolve inside the root they were found in.

    Applied to the files a group would actually report, not to every candidate:
    `is_within()` resolves real paths, and doing that for ~16k candidates costs
    several seconds, while doing it for the few thousand reported paths is
    free. The check exists so a reparse point or a symlinked tree can never
    make this module name a file outside the root that owns it.
    """
    out: list[dict] = []
    for c in items:
        try:
            if is_within(c["path"], [c["root"]]):
                out.append(c)
        except (OSError, ValueError):
            continue
    return out


def _group(items: list[dict], digest: str) -> dict:
    items = sorted(items, key=lambda c: (c["mtime"], c["path"]))
    size = int(items[0]["size"])
    count = len(items)
    wasted = size * (count - 1)
    return {
        "hash": digest,
        "size": size,
        "size_h": human_size(size),
        "count": count,
        "wasted": wasted,
        "wasted_h": human_size(wasted),
        "paths": [
            {
                "path": c["path"],
                "agent": c["agent"],
                "mtime": c["mtime"],
                "mtime_iso": ms_to_iso(c["mtime"]),
            }
            for c in items
        ],
        "kind": _kind_for(items),
    }


def find(min_bytes: int = 4096, limit: int = 20000) -> dict:
    """Find groups of byte-identical files at or above `min_bytes`.

    Returns groups sorted by reclaimed space (largest first), capped at
    MAX_GROUPS. Read-only: nothing on disk is modified.
    """
    try:
        floor = max(1, int(min_bytes))
    except (TypeError, ValueError):
        floor = 4096
    try:
        cap = max(1, int(limit))
    except (TypeError, ValueError):
        cap = 20000
    if cap > MAX_GROUPS * 200:
        cap = MAX_GROUPS * 200

    result = {
        "groups": [],
        "scanned_files": 0,
        "candidate_files": 0,
        "wasted_bytes": 0,
        "wasted_bytes_h": human_size(0),
        "note": "",
    }

    try:
        candidates, scanned, errors, truncated = _collect(floor, cap)
        result["scanned_files"] = scanned
        result["candidate_files"] = len(candidates)

        # Phase 1: exact size. A size with a single member cannot be a
        # duplicate, so it never gets read.
        by_size: dict[int, list[dict]] = {}
        for c in candidates:
            by_size.setdefault(c["size"], []).append(c)

        groups: list[dict] = []
        for size, items in by_size.items():
            if len(items) < 2:
                continue
            # Phase 2a: compare the first 64 KiB only.
            buckets: dict[str, list[dict]] = {}
            for c in items:
                digest = _hash_file(c["path"], PREFIX_BYTES)
                if digest is None:
                    errors += 1
                    continue
                buckets.setdefault(digest, []).append(c)

            for prefix_digest, bucket in buckets.items():
                if len(bucket) < 2:
                    continue
                if size <= PREFIX_BYTES:
                    # The prefix *is* the file: it is already confirmed.
                    ok = _contained(bucket)
                    if len(ok) >= 2:
                        groups.append(_group(ok, prefix_digest))
                    continue
                # Phase 2b: confirm with a full read.
                full: dict[str, list[dict]] = {}
                for c in bucket:
                    digest = _hash_file(c["path"])
                    if digest is None:
                        errors += 1
                        continue
                    full.setdefault(digest, []).append(c)
                for digest, confirmed in full.items():
                    if len(confirmed) < 2:
                        continue
                    ok = _contained(confirmed)
                    if len(ok) >= 2:
                        groups.append(_group(ok, digest))

        groups.sort(key=lambda g: (-g["wasted"], -g["size"], g["paths"][0]["path"]))
        groups = groups[:MAX_GROUPS]
        result["groups"] = groups
        total = sum(g["wasted"] for g in groups)
        result["wasted_bytes"] = total
        result["wasted_bytes_h"] = human_size(total)

        notes: list[str] = []
        if groups:
            notes.append(
                f"发现 {len(groups)} 组重复内容，合计可回收约 {human_size(total)}。"
                "本模块只读，不会删除任何文件；请在人工复核后交由执行器处理。"
            )
        else:
            notes.append(
                "未发现满足条件的重复内容。本模块只读，不会删除任何文件。"
            )
        if truncated:
            notes.append(f"候选文件已达到上限 {cap} 个，扫描提前结束，结果可能不完整。")
        if errors:
            notes.append(f"有 {errors} 个文件或目录无法访问，已跳过。")
        result["note"] = "".join(notes)
        return result
    except Exception as e:  # a report must never break the caller
        result["note"] = f"扫描重复内容失败：{type(e).__name__}。"
        return result
