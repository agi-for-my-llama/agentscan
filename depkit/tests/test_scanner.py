from pathlib import Path

from depkit.models import DependencyKind, Ecosystem
from depkit.scanner import scan


def test_scan_finds_supported_dependency_files() -> None:
    root = Path(__file__).parents[1] / "examples" / "polyglot-app"

    deps = scan(root)
    names = {(dep.ecosystem, dep.name) for dep in deps}

    assert (Ecosystem.NODE, "next") in names
    assert (Ecosystem.PYTHON, "fastapi") in names
    assert (Ecosystem.GO, "go") in names
    assert (Ecosystem.DOCKER, "node") in names
    assert (Ecosystem.GITHUB_ACTIONS, "actions/setup-node") in names
    assert any(dep.name == "node" and dep.kind is DependencyKind.RUNTIME for dep in deps)
