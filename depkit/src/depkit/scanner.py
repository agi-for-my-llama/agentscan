from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from depkit.models import Dependency
from depkit.parsers import (
    parse_dockerfile,
    parse_github_workflow,
    parse_go_mod,
    parse_package_json,
    parse_pyproject_toml,
    parse_requirements_txt,
)

Parser = Callable[[Path], list[Dependency]]


IGNORED_DIRS = {".git", ".venv", "dist", "node_modules", "__pycache__"}


def scan(root: Path) -> list[Dependency]:
    root = root.resolve()
    dependencies: list[Dependency] = []
    for path in root.rglob("*"):
        if not path.is_file() or _is_ignored(path, root):
            continue
        parser = _parser_for(path)
        if not parser:
            continue
        try:
            dependencies.extend(parser(path))
        except (OSError, ValueError):
            continue
    return sorted(dependencies, key=lambda dep: (str(dep.source), dep.ecosystem, dep.name))


def _parser_for(path: Path) -> Parser | None:
    name = path.name
    if name == "package.json":
        return parse_package_json
    if name == "requirements.txt":
        return parse_requirements_txt
    if name == "pyproject.toml":
        return parse_pyproject_toml
    if name == "go.mod":
        return parse_go_mod
    if name == "Dockerfile" or name.endswith(".Dockerfile"):
        return parse_dockerfile
    if path.suffix in {".yml", ".yaml"} and ".github" in path.parts and "workflows" in path.parts:
        return parse_github_workflow
    return None


def _is_ignored(path: Path, root: Path) -> bool:
    try:
        rel = path.relative_to(root)
    except ValueError:
        return True
    return bool(set(rel.parts) & IGNORED_DIRS)
