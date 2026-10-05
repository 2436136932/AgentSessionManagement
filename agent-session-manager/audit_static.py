"""Static audit: import every module, then check each for undefined names.

Catches the class of bug that a passing test suite can still miss -- code paths
that are only reached in production (e.g. a helper used on an error path).

Run:  python audit_static.py
"""

from __future__ import annotations

import ast
import builtins
import importlib
import pkgutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

FAILURES: list[str] = []


def modules() -> list[str]:
    """Library modules to import-check.

    The `selftest_*.py` scripts are deliberately excluded. They are programs,
    not libraries: importing one runs its sandbox setup (redirecting
    USERPROFILE/APPDATA and creating a temp directory) as a side effect, and
    only `__main__` tears that down -- so importing them here leaked an empty
    sandbox per run. They are still fully covered by the AST passes below,
    which need no import.
    """
    names = []
    for pkg in ("core", "adapters"):
        for info in pkgutil.iter_modules([str(ROOT / pkg)]):
            names.append(f"{pkg}.{info.name}")
    names += ["server"]
    return names


def script_files() -> list[str]:
    """Entry-point scripts checked for syntax only (never imported)."""
    return [
        "run_all_tests",
        "audit_static",
        "selftest_scan",
        "selftest_preview",
        "selftest_safety",
        "selftest_hostile",
        "selftest_delete",
        "selftest_sqlite",
        "selftest_realdb",
    ]


def undefined_names(path: Path) -> list[tuple[int, str]]:
    """Approximate undefined-name check via AST scope analysis.

    Collects every module-level and imported binding plus builtins, then looks
    for Name loads that are not bound anywhere in the file and are not locals,
    attributes, or comprehension targets.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError as e:
        return [(e.lineno or 0, f"SyntaxError: {e.msg}")]

    bound: set[str] = set(dir(builtins))
    # Module-level implicits that are not in `builtins`.
    bound |= {"__file__", "__name__", "__doc__", "__package__", "__spec__", "__loader__"}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for a in node.names:
                bound.add((a.asname or a.name).split(".")[0])
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = node.args
                for a in (
                    list(args.posonlyargs)
                    + list(args.args)
                    + list(args.kwonlyargs)
                ):
                    bound.add(a.arg)
                if args.vararg:
                    bound.add(args.vararg.arg)
                if args.kwarg:
                    bound.add(args.kwarg.arg)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)
        elif isinstance(node, (ast.For, ast.AsyncFor)) and isinstance(node.target, ast.Name):
            bound.add(node.target.id)
        elif isinstance(node, ast.withitem) and node.optional_vars is not None:
            if isinstance(node.optional_vars, ast.Name):
                bound.add(node.optional_vars.id)
        elif isinstance(node, ast.Global):
            bound.update(node.names)
        elif isinstance(node, ast.Lambda):
            for a in list(node.args.args) + list(node.args.kwonlyargs):
                bound.add(a.arg)

    # Local function/class scope names are added above via walk, which is a
    # deliberate over-approximation: this audit targets module-level typos and
    # helpers that were renamed without updating call sites.
    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id not in bound:
                out.append((node.lineno, node.id))
    return out


def unused_imports(path: Path) -> list[tuple[int, str]]:
    """Imported names that are never referenced again in the file.

    `from __future__ import annotations` is exempt: it has an effect without
    being referenced.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        return []

    imported: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imported[(a.asname or a.name).split(".")[0]] = node.lineno
        elif isinstance(node, ast.ImportFrom):
            if node.module == "__future__":
                continue
            for a in node.names:
                if a.name == "*":
                    continue
                imported[a.asname or a.name] = node.lineno

    used: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
        elif isinstance(node, ast.Attribute):
            base = node
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name):
                used.add(base.id)
    # A name may also appear only inside a string annotation.
    text = path.read_text(encoding="utf-8")

    out: list[tuple[int, str]] = []
    for name, lineno in imported.items():
        if name in used:
            continue
        if text.count(name) > 1:  # used in a string annotation / docstring
            continue
        out.append((lineno, name))
    return out


def main() -> int:
    print("=" * 74)
    print("STATIC AUDIT")
    print("=" * 74)

    print("\n[1] importing every library module")
    for name in modules():
        try:
            importlib.import_module(name)
            print(f"  [PASS] import {name}")
        except Exception as e:
            FAILURES.append(f"import {name}: {e}")
            print(f"  [FAIL] import {name}: {type(e).__name__}: {e}")

    print("\n[1b] syntax-checking entry-point scripts (not imported: they have "
          "import-time side effects)")
    for name in script_files():
        p = ROOT / f"{name}.py"
        try:
            ast.parse(p.read_text(encoding="utf-8"))
            print(f"  [PASS] parse {name}.py")
        except SyntaxError as e:
            FAILURES.append(f"parse {name}.py: {e}")
            print(f"  [FAIL] parse {name}.py: {e}")

    files = sorted(f for f in ROOT.rglob("*.py") if "__pycache__" not in str(f))

    print("\n[2] undefined-name scan")
    total = 0
    for f in files:
        bad = undefined_names(f)
        # Filter obvious false positives from the over-approximation above.
        bad = [(ln, n) for ln, n in bad if n not in ("self", "cls")]
        if bad:
            total += len(bad)
            for ln, n in sorted(set(bad)):
                rel = f.relative_to(ROOT)
                FAILURES.append(f"{rel}:{ln} undefined name {n!r}")
                print(f"  [FAIL] {rel}:{ln}: undefined name {n!r}")
    if not total:
        print(f"  [PASS] no undefined names across {len(files)} files")

    print("\n[3] unused-import scan")
    total = 0
    for f in files:
        bad = unused_imports(f)
        if bad:
            total += len(bad)
            for ln, n in sorted(bad):
                rel = f.relative_to(ROOT)
                FAILURES.append(f"{rel}:{ln} unused import {n!r}")
                print(f"  [FAIL] {rel}:{ln}: unused import {n!r}")
    if not total:
        print(f"  [PASS] no unused imports across {len(files)} files")

    print("\n" + "=" * 74)
    if FAILURES:
        print(f"RESULT: {len(FAILURES)} issue(s)")
        for x in FAILURES:
            print(f"  - {x}")
        return 1
    print("RESULT: static audit clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
