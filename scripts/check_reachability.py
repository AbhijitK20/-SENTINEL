"""Which modules can the product actually reach?

This project grew a large amount of code that looks like a capability and is
imported by nothing. A hand-rolled GAT, a second RBAC system, a SQLAlchemy ORM
on an uninstalled driver, a Prometheus metric catalogue, a capacity table citing
load tests that were never written. None of it was reachable, and nothing failed
when that was true - a reader could not tell the difference from a feature.

So reachability becomes a build failure. This walks the import graph with ``ast``
and computes the transitive closure from the real entry points:

* ``src/sentinel/dashboard/app.py`` - the Streamlit console
* ``src/sentinel/api/app.py``       - the FastAPI service
* every ``scripts/*.py``            - the CLIs

A module that only a test imports is **unreachable**, which is the point: being
exercised by ``tests/`` is not the same as being used. Anything legitimate that
cannot be reached must be listed in ``ALLOWLIST`` with a reason that survives
review, so the exception is a deliberate decision rather than an oversight.

    uv run python scripts/check_reachability.py          # report
    uv run python scripts/check_reachability.py --strict  # exit 1 if unreachable
"""

from __future__ import annotations

import argparse
import ast
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_NAME = "sentinel"
# The package directory itself, so relative paths do not gain a second
# `sentinel.` prefix when converted to dotted module names.
PACKAGE_ROOT = ROOT / "src" / PACKAGE_NAME
SCRIPTS_DIR = ROOT / "scripts"
TESTS_DIR = ROOT / "tests"

# The two long-running entry points, by module path.
APP_ENTRY_POINTS = (
    "sentinel.dashboard.app",
    "sentinel.api.app",
)

# Deliberate exceptions. Empty by design: every entry is a decision someone
# made, and adding one is a reviewable act. Currently none are needed - after
# the Sprint 1 purge every module is reachable from an entry point.
ALLOWLIST: dict[str, str] = {}


@dataclass
class Graph:
    """The import graph, keyed by dotted module name."""

    paths: dict[str, Path] = field(default_factory=dict)
    imports: dict[str, set[str]] = field(default_factory=dict)

    def closure(self, roots: Iterable[str]) -> set[str]:
        seen: set[str] = set()
        pending = list(roots)
        while pending:
            current = pending.pop()
            if current in seen or current not in self.paths:
                continue
            seen.add(current)
            pending.extend(self.imports.get(current, ()))
        return seen


def module_name_for(path: Path) -> str | None:
    """``src/sentinel/api/app.py`` -> ``sentinel.api.app``."""
    try:
        relative = path.relative_to(PACKAGE_ROOT)
    except ValueError:
        return None
    parts = list(relative.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    # ``src/sentinel/__init__.py`` reduces to no parts; it is still a module
    # (the package itself) and is executed by any `sentinel.*` import.
    return ".".join([PACKAGE_NAME, *parts])


def _imported_names(node: ast.AST, current_module: str, is_package: bool) -> set[str]:
    """Every module this import statement touches, resolved to a dotted name.

    ``from sentinel.predict import forecast`` depends on ``sentinel.predict`` -
    not on a module called ``sentinel.predict.forecast``, which does not exist.
    Getting this wrong is how reachability tools end up reporting everything as
    reachable, so relative imports and package ``__init__`` are handled here
    rather than skipped.
    """
    found: set[str] = set()
    if isinstance(node, ast.Import):
        for alias in node.names:
            if alias.name.split(".")[0] == PACKAGE_NAME:
                found.add(alias.name)
        return found
    if isinstance(node, ast.ImportFrom):
        if node.level:
            # Relative: resolve against the importing module's package.
            base = current_module if is_package else current_module.rsplit(".", 1)[0]
            anchor = base if not node.level or node.level == 1 else base
            for _ in range(node.level - 1):
                anchor = anchor.rsplit(".", 1)[0]
            prefix = f"{anchor}.{node.module}" if node.module else anchor
        else:
            if node.module is None or node.module.split(".")[0] != PACKAGE_NAME:
                return found
            prefix = node.module
        found.add(prefix)
        # `from pkg import submodule` may be importing a real module, not a name.
        for alias in node.names:
            candidate = f"{prefix}.{alias.name}"
            found.add(candidate)
        return found
    return found


def build_graph() -> Graph:
    graph = Graph()
    files = sorted(PACKAGE_ROOT.rglob("*.py"))
    for path in files:
        module = module_name_for(path)
        if module:
            graph.paths[module] = path

    for module, path in graph.paths.items():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as error:  # pragma: no cover - a parse error is a bug
            raise SystemExit(f"cannot parse {path}: {error}") from error
        is_package = path.name == "__init__.py"
        edges: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                edges |= _imported_names(node, module, is_package)
        # Resolve to real modules: an import of a name inside a module is not an
        # edge to a module.
        graph.imports[module] = {e for e in edges if e in graph.paths and e != module}
    return graph


def script_entry_points() -> list[str]:
    """Script modules count as roots - they are the CLIs users run."""
    roots: list[str] = []
    for path in sorted(SCRIPTS_DIR.glob("*.py")):
        # Scripts import `sentinel.*` but are not themselves importable as a
        # package, so their own edges are gathered separately by parse_scratch.
        roots.append(f"<script>{path.stem}")
    return roots


def parse_scripts(graph: Graph) -> dict[str, set[str]]:
    """Edges contributed by ``scripts/``, keyed by ``<script>name``."""
    edges: dict[str, set[str]] = {}
    for path in sorted(SCRIPTS_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        found: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                found |= _imported_names(node, f"{PACKAGE_NAME}.scripts", False)
        edges[f"<script>{path.stem}"] = {e for e in found if e in graph.paths}
    return edges


def test_only_modules(graph: Graph) -> set[str]:
    """Modules the test suite imports that no entry point reaches."""
    imported: set[str] = set()
    for path in sorted(TESTS_DIR.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                imported |= _imported_names(node, f"{PACKAGE_NAME}.tests", False)
    return {m for m in imported if m in graph.paths}


def _with_parents(modules: set[str]) -> set[str]:
    """Add every parent package of every module.

    Importing ``sentinel.world_model.model`` executes
    ``sentinel/world_model/__init__.py`` on the way, so a package initializer
    whose package holds a reachable module is never dead. Without this, every
    ``__init__.py`` looks orphaned and the tool cries wolf on files that are
    structurally required.
    """
    expanded = set(modules)
    for module in modules:
        parts = module.split(".")
        for depth in range(1, len(parts) + 1):
            expanded.add(".".join(parts[:depth]))
    return expanded


def analyse() -> tuple[list[tuple[str, str]], set[str]]:
    """Return (unreachable modules with their reason, reachable modules)."""
    graph = build_graph()
    script_edges = parse_scripts(graph)
    script_roots = [root for root, edges in script_edges.items() if edges]
    roots = [m for m in APP_ENTRY_POINTS if m in graph.paths] + script_roots

    reachable = graph.closure(roots)
    # Scripts reach whatever they import; add those edges into the closure.
    pending = [edge for root in script_roots for edge in script_edges[root]]
    while pending:
        current = pending.pop()
        if current in reachable:
            continue
        reachable.add(current)
        pending.extend(graph.imports.get(current, ()))
    reachable = _with_parents(reachable)

    unreachable: list[tuple[str, str]] = []
    for module in sorted(set(graph.paths) - reachable):
        if module in ALLOWLIST:
            continue
        relative = graph.paths[module].relative_to(ROOT)
        in_tests = module in test_only_modules(graph)
        reason = "imported only by tests" if in_tests else "imported by nothing"
        unreachable.append((f"{relative}", reason))
    return unreachable, reachable


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit non-zero when any module is unreachable",
    )
    args = parser.parse_args(argv)

    unreachable, reachable = analyse()
    graph = build_graph()
    total_lines = sum(len(p.read_text(encoding="utf-8").splitlines()) for p in graph.paths.values())
    print(f"modules: {len(graph.paths)}   reachable: {len(reachable)}   lines: {total_lines}")
    if not unreachable:
        print("REACHABILITY PASSED: every module is reachable from an entry point")
        return
    print(f"\nUNREACHABLE ({len(unreachable)}):")
    for name, reason in unreachable:
        print(f"  {name:<52} {reason}")
    if args.strict:
        print(
            "\nEvery module must be reachable from an entry point, or listed in "
            "ALLOWLIST with a reason."
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
