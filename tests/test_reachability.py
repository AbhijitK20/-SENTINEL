# SPDX-License-Identifier: Apache-2.0
"""Reachability is a build failure, not a review question.

This repository carried roughly 2,800 lines that looked like capability and was
imported by nothing: a hand-rolled GAT, a second RBAC system, a SQLAlchemy ORM
on a driver that is not installed, a Prometheus metric catalogue, a capacity
table citing load tests nobody ran, and a STRIDE table listing mitigations that
were never built. None of it was reachable, and nothing failed - a reader could
not tell it apart from a feature.

So "is this module used?" is answered by the build. These tests make the answer
enforced rather than remembered.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "sentinel_reachability",
    Path(__file__).resolve().parents[1] / "scripts" / "check_reachability.py",
)
assert _SPEC and _SPEC.loader
reach = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = reach
_SPEC.loader.exec_module(reach)


def test_every_module_is_reachable_from_an_entry_point() -> None:
    unreachable, reachable = reach.analyse()
    assert not unreachable, (
        "these modules cannot be reached from dashboard/app.py, api/app.py or any "
        "script, so nothing in the product can use them. Wire them in, delete "
        "them, or - if the exception is deliberate - add them to ALLOWLIST in "
        "scripts/check_reachability.py with a reason that survives review:\n  "
        + "\n  ".join(f"{name} ({reason})" for name, reason in unreachable)
    )
    assert reachable


def test_the_allowlist_is_empty() -> None:
    # A growing allowlist is how this check quietly stops working. Every entry
    # is a decision someone made, so the list is expected to be empty and any
    # addition is a visible diff.
    assert reach.ALLOWLIST == {}, (
        f"ALLOWLIST has grown: {reach.ALLOWLIST}. An unreachable module needs a "
        "reason, and 'we might use it' is not one."
    )


def test_the_two_entry_points_exist() -> None:
    graph = reach.build_graph()
    for entry in reach.APP_ENTRY_POINTS:
        assert entry in graph.paths, f"entry point {entry} is missing - has the app moved?"


def test_scripts_are_treated_as_entry_points() -> None:
    # A CLI is a real entry point. If the tool stopped counting scripts, every
    # module used only by a command would look dead.
    graph = reach.build_graph()
    edges = reach.parse_scripts(graph)
    assert len(edges) > 20, "the script scan found almost nothing; the tool is broken"
    contributing = [root for root, found in edges.items() if found]
    assert contributing


def test_package_initializers_are_not_counted_as_dead() -> None:
    """Importing a submodule executes its package ``__init__``.

    A tool that reports ``world_model/__init__.py`` as unreachable is wrong, and
    would push someone to delete a file the interpreter requires.
    """
    graph = reach.build_graph()
    assert "sentinel.world_model.model" in graph.paths
    expanded = reach._with_parents({"sentinel.world_model.model"})
    assert "sentinel.world_model" in expanded
    assert "sentinel" in expanded


def test_the_gate_exits_non_zero_when_something_is_dead(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        reach, "analyse", lambda: ([("src/sentinel/fake.py", "imported by nothing")], set())
    )
    with pytest.raises(SystemExit) as exit_info:
        reach.main(["--strict"])
    assert exit_info.value.code == 1
    assert "UNREACHABLE" in capsys.readouterr().out


def test_relative_imports_resolve_to_a_real_package() -> None:
    # api/__init__.py uses a relative import. Resolving it to the wrong name
    # would mark the API app unreachable and hide a genuine break.
    import ast

    tree = ast.parse("from .app import create_app")
    names = reach._imported_names(tree.body[0], "sentinel.api", True)
    assert "sentinel.api.app" in names
