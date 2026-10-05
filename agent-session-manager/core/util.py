"""Shared helpers: paths, sizes, atomic I/O, safety checks.

No third-party dependencies. Python 3.14 stdlib only.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

# --------------------------------------------------------------------------
# Environment
# --------------------------------------------------------------------------


def home() -> Path:
    return Path(os.path.expanduser("~"))


def local_appdata() -> Path:
    return Path(os.environ.get("LOCALAPPDATA", home() / "AppData" / "Local"))


def roaming_appdata() -> Path:
    return Path(os.environ.get("APPDATA", home() / "AppData" / "Roaming"))


def program_data() -> Path:
    return Path(os.environ.get("ProgramData", r"C:\ProgramData"))


def app_root() -> Path:
    """Project root (parent of core/)."""
    return Path(__file__).resolve().parent.parent


def data_root() -> Path:
    """Where the tool keeps its own state: quarantine, journal, exports."""
    p = app_root() / "_data"
    p.mkdir(parents=True, exist_ok=True)
    return p


def quarantine_root() -> Path:
    p = data_root() / "quarantine"
    p.mkdir(parents=True, exist_ok=True)
    return p


def journal_path() -> Path:
    return data_root() / "operations.jsonl"


# --------------------------------------------------------------------------
# Formatting
# --------------------------------------------------------------------------


def human_size(n: int | float | None) -> str:
    if not n:
        return "0 B"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            if unit == "B":
                return f"{int(n)} {unit}"
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def ms_to_iso(ms: int | float | None) -> str:
    """Epoch-milliseconds -> local ISO-ish string."""
    if not ms or ms < 0:
        return ""
    try:
        return datetime.fromtimestamp(ms / 1000.0).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return ""


def ms_to_epoch(ms: int | float | None) -> float:
    if not ms or ms < 0:
        return 0.0
    return float(ms) / 1000.0


def now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def now_ms() -> int:
    return int(time.time() * 1000)


# --------------------------------------------------------------------------
# Filesystem
# --------------------------------------------------------------------------


def dir_size(root: Path) -> tuple[int, int]:
    """Return (total_bytes, file_count). Never raises."""
    total = 0
    count = 0
    if not root.exists():
        return 0, 0
    try:
        if root.is_file():
            try:
                return root.stat().st_size, 1
            except OSError:
                return 0, 0
        for dirpath, _dirnames, filenames in os.walk(root, onerror=lambda e: None):
            for fn in filenames:
                try:
                    total += os.path.getsize(os.path.join(dirpath, fn))
                    count += 1
                except OSError:
                    continue
    except OSError:
        pass
    return total, count


def safe_size(p: Path) -> int:
    try:
        if p.is_file():
            return p.stat().st_size
    except OSError:
        pass
    return 0


def norm(p: str | Path) -> str:
    """Normalised absolute path string for comparison (case-insensitive on Windows)."""
    s = str(Path(p).absolute())
    return os.path.normcase(os.path.normpath(s))


def is_within(path: str | Path, roots: list[Path]) -> bool:
    """True when `path` is equal to, or strictly inside, one of `roots`.

    This is the guard that stops a malformed session id from escaping an
    agent's data directory. Comparison is case-insensitive on Windows and
    operates on fully resolved paths.
    """
    try:
        target = Path(path).resolve()
    except (OSError, ValueError):
        return False
    tn = norm(target)
    for r in roots:
        try:
            rn = norm(Path(r).resolve())
        except (OSError, ValueError):
            continue
        if tn == rn or tn.startswith(rn + os.sep):
            return True
    return False


def is_safe_session_id(sid: str) -> bool:
    """A session id that is safe to use as a *path component*.

    Used when an adapter composes a filesystem path from the id, so any
    separator, drive colon, wildcard or control character is refused.
    """
    if not sid or not isinstance(sid, str):
        return False
    if len(sid) > 200:
        return False
    if sid in (".", ".."):
        return False
    if any(c in sid for c in ("/", "\\", "\0", ":", "*", "?", '"', "<", ">", "|")):
        return False
    return True


def is_safe_key(sid: str) -> bool:
    """A session id that is only ever used as a lookup key, never a path.

    Some stores identify sessions with values that are illegal in a filename
    but perfectly valid as a database or JSON key. VS Code, for example, uses
    ids like "agent-host-copilotcli:/untitled-<uuid>". Rejecting those would
    make exactly the entries this tool needs to clean up undeletable.

    Keys are only ever used as: a parameter to a SQLite WHERE clause, a JSON
    object key, or a list-member comparison. None of those can escape a
    container. The checks kept here are defence in depth:

      * no NUL / newline / other control characters (corrupts blobs and logs)
      * no backslash (a Windows path separator with no legitimate use in an id)
      * no ".." (path-traversal sequence)
      * no leading/trailing whitespace, sane length

    "/" and ":" are permitted because real ids contain them. Any *path* an
    adapter derives is validated separately against the agent's roots by
    Executor.validate(), which is the check that actually prevents escape.
    """
    if not sid or not isinstance(sid, str):
        return False
    if len(sid) > 400:
        return False
    if sid.strip() != sid:
        return False
    if "\0" in sid or "\n" in sid or "\r" in sid:
        return False
    if "\\" in sid:
        return False
    if ".." in sid:
        return False
    if any(ord(c) < 32 or ord(c) == 127 for c in sid):
        return False
    return True


def listdir(p: Path) -> list[Path]:
    try:
        return sorted(p.iterdir())
    except OSError:
        return []


def list_files(p: Path, suffix: str | None = None) -> list[Path]:
    try:
        items = [x for x in p.iterdir() if x.is_file()]
    except OSError:
        return []
    if suffix:
        items = [x for x in items if x.name.lower().endswith(suffix.lower())]
    return sorted(items)


def list_dirs(p: Path) -> list[Path]:
    try:
        return sorted([x for x in p.iterdir() if x.is_dir()])
    except OSError:
        return []


# --------------------------------------------------------------------------
# Atomic JSON
# --------------------------------------------------------------------------


def read_json(p: Path, default=None):
    try:
        with open(p, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def write_json_atomic(p: Path, obj) -> None:
    """Write JSON via temp file + os.replace so a crash cannot truncate it.

    A .bak copy of the previous content is kept alongside.
    """
    p = Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists():
        try:
            shutil.copy2(p, p.with_suffix(p.suffix + ".bak"))
        except OSError:
            pass
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".tmp-", suffix=p.suffix)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, ensure_ascii=False, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def append_jsonl(p: Path, obj) -> None:
    p = Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, ensure_ascii=False) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def read_jsonl(p: Path) -> list[dict]:
    out: list[dict] = []
    try:
        with open(p, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        pass
    return out


# --------------------------------------------------------------------------
# PowerShell access
# --------------------------------------------------------------------------
# PowerShell 7 (pwsh) is not always on PATH for child processes -- on this
# machine the harness runs its own bundled pwsh, but subprocess cannot resolve
# it, while Windows PowerShell 5.1 is always present. Resolve once, preferring
# pwsh when it is genuinely reachable.

_PS_CACHE: dict = {"exe": None, "checked": False}


def powershell_exe() -> str | None:
    """Absolute path of a usable PowerShell, or None."""
    if _PS_CACHE["checked"]:
        return _PS_CACHE["exe"]
    _PS_CACHE["checked"] = True

    import shutil as _sh

    candidates = [
        _sh.which("pwsh"),
        os.path.join(
            os.environ.get("ProgramFiles", r"C:\Program Files"),
            "PowerShell", "7", "pwsh.exe",
        ),
        os.path.join(
            os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
            "PowerShell", "7", "pwsh.exe",
        ),
        _sh.which("powershell"),
        os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"),
            "System32", "WindowsPowerShell", "v1.0", "powershell.exe",
        ),
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            _PS_CACHE["exe"] = c
            return c
    return None


def run_powershell(script: str, timeout: int = 90) -> str:
    """Run a PowerShell script and return stdout (UTF-8), or '' on failure.

    The script is passed via -EncodedCommand so that quoting, backslashes and
    non-ASCII text survive intact regardless of the host code page.
    """
    exe = powershell_exe()
    if not exe:
        return ""
    import base64
    import subprocess

    preamble = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
    encoded = base64.b64encode((preamble + script).encode("utf-16-le")).decode("ascii")
    try:
        out = subprocess.run(
            [exe, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            capture_output=True,
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return (out.stdout or b"").decode("utf-8", "replace")
    except Exception:
        return ""


# --------------------------------------------------------------------------
# Process detection
# --------------------------------------------------------------------------

_PROC_CACHE: dict = {"at": 0.0, "names": set()}
_PROC_TTL = 3.0


def running_process_names(force: bool = False) -> set[str]:
    """Lowercased set of running executable names.

    Cached briefly: every adapter asks this question during a report, and
    spawning a process per adapter made a single page load take over a second.
    """
    import time as _t

    now = _t.time()
    if not force and _PROC_CACHE["names"] and (now - _PROC_CACHE["at"]) < _PROC_TTL:
        return _PROC_CACHE["names"]

    names: set[str] = set()
    text = run_powershell("Get-Process | Select-Object -ExpandProperty ProcessName")
    for line in text.splitlines():
        line = line.strip()
        if line:
            names.add(line.lower())

    if not names:
        # Portable fallback that does not need PowerShell at all.
        try:
            import subprocess

            out = subprocess.run(
                ["tasklist", "/fo", "csv", "/nh"],
                capture_output=True,
                timeout=30,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            raw = (out.stdout or b"").decode("utf-8", "replace")
            for line in raw.splitlines():
                line = line.strip()
                if line.startswith('"'):
                    name = line.split('","')[0].strip('"')
                    if name:
                        names.add(name.lower())
        except Exception:
            pass

    # Store both the bare name and the ".exe" form. Get-Process returns names
    # without the extension ("deepseek harness") while tasklist includes it
    # ("deepseek harness.exe"), and adapters may declare either.
    expanded = set(names)
    for n in names:
        if n.endswith(".exe"):
            expanded.add(n[:-4])
        else:
            expanded.add(n + ".exe")
    names = expanded

    _PROC_CACHE["names"] = names
    _PROC_CACHE["at"] = now
    return names


# --------------------------------------------------------------------------
# Path safety helpers used by the planner
# --------------------------------------------------------------------------


def display_path(p: Path | str) -> str:
    """Shorten a path for display, keeping it unambiguous."""
    s = str(p)
    h = str(home())
    if s.lower().startswith(h.lower()):
        return "~" + s[len(h):]
    return s


def ensure_empty_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def remove_tree(p: Path, retries: int = 4, delay: float = 0.2) -> str | None:
    """Delete a directory tree, retrying briefly on Windows lock errors.

    Returns None on success, or the last error message. `ignore_errors=True`
    is deliberately NOT used: a silently failed delete is how empty skeletons
    pile up in a quarantine or temp directory, which is exactly the class of
    residue this tool exists to eliminate.
    """
    import shutil as _sh
    import time as _t

    if not p.exists():
        return None
    last = ""
    for attempt in range(retries):
        try:
            _sh.rmtree(p)
            return None
        except FileNotFoundError:
            return None
        except OSError as e:
            last = f"{type(e).__name__}: {e}"
            if attempt < retries - 1:
                _t.sleep(delay * (attempt + 1))
    return last or "unknown error"


def which(name: str) -> str | None:
    return shutil.which(name)


def plat() -> str:
    return sys.platform
