from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from depkit.models import Dependency, DependencyKind, Ecosystem


ACTION_USES_RE = re.compile(r"uses:\s*([\w.-]+/[\w.-]+)@([^\s#]+)")
DOCKER_FROM_RE = re.compile(r"^\s*FROM\s+([^\s:]+)(?::([^\s]+))?", re.IGNORECASE)
GO_REQUIRE_RE = re.compile(r"^\s*([\w./-]+)\s+(v[^\s]+)")
PY_REQ_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*([<>=!~]=?.*)?$")


def parse_package_json(path: Path) -> list[Dependency]:
    data = json.loads(path.read_text(encoding="utf-8"))
    found: list[Dependency] = []
    for section, kind in (
        ("dependencies", DependencyKind.APPLICATION),
        ("devDependencies", DependencyKind.DEV),
        ("peerDependencies", DependencyKind.APPLICATION),
    ):
        for name, constraint in data.get(section, {}).items():
            found.append(
                Dependency(
                    name=name,
                    version=_strip_constraint(str(constraint)),
                    ecosystem=Ecosystem.NODE,
                    kind=kind,
                    source=path,
                    constraint=str(constraint),
                )
            )

    engines = data.get("engines", {})
    if "node" in engines:
        found.append(
            Dependency(
                name="node",
                version=_strip_constraint(str(engines["node"])),
                ecosystem=Ecosystem.NODE,
                kind=DependencyKind.RUNTIME,
                source=path,
                constraint=str(engines["node"]),
            )
        )
    return found


def parse_requirements_txt(path: Path) -> list[Dependency]:
    found: list[Dependency] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        clean = line.split("#", 1)[0].strip()
        if not clean or clean.startswith(("-", "git+", "http")):
            continue
        match = PY_REQ_RE.match(clean)
        if not match:
            continue
        name, constraint = match.groups()
        found.append(
            Dependency(
                name=name,
                version=_strip_constraint(constraint or ""),
                ecosystem=Ecosystem.PYTHON,
                kind=DependencyKind.APPLICATION,
                source=path,
                constraint=constraint,
            )
        )
    return found


def parse_pyproject_toml(path: Path) -> list[Dependency]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    project = data.get("project", {})
    found = [_python_dep(dep, path) for dep in project.get("dependencies", [])]

    requires_python = project.get("requires-python")
    if requires_python:
        found.append(
            Dependency(
                name="python",
                version=_strip_constraint(str(requires_python)),
                ecosystem=Ecosystem.PYTHON,
                kind=DependencyKind.RUNTIME,
                source=path,
                constraint=str(requires_python),
            )
        )

    optional = project.get("optional-dependencies", {})
    for deps in optional.values():
        found.extend(_python_dep(dep, path, DependencyKind.DEV) for dep in deps)
    return found


def parse_go_mod(path: Path) -> list[Dependency]:
    found: list[Dependency] = []
    in_block = False
    for line in path.read_text(encoding="utf-8").splitlines():
        clean = line.split("//", 1)[0].strip()
        if clean.startswith("go "):
            found.append(
                Dependency(
                    name="go",
                    version=clean.removeprefix("go ").strip(),
                    ecosystem=Ecosystem.GO,
                    kind=DependencyKind.RUNTIME,
                    source=path,
                )
            )
            continue
        if clean == "require (":
            in_block = True
            continue
        if in_block and clean == ")":
            in_block = False
            continue
        if clean.startswith("require "):
            clean = clean.removeprefix("require ").strip()
        if in_block or "/" in clean:
            match = GO_REQUIRE_RE.match(clean)
            if match:
                found.append(
                    Dependency(
                        name=match.group(1),
                        version=match.group(2),
                        ecosystem=Ecosystem.GO,
                        kind=DependencyKind.APPLICATION,
                        source=path,
                    )
                )
    return found


def parse_dockerfile(path: Path) -> list[Dependency]:
    found: list[Dependency] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = DOCKER_FROM_RE.match(line)
        if match:
            image, tag = match.groups()
            found.append(
                Dependency(
                    name=image,
                    version=tag or "latest",
                    ecosystem=Ecosystem.DOCKER,
                    kind=DependencyKind.RUNTIME,
                    source=path,
                )
            )
    return found


def parse_github_workflow(path: Path) -> list[Dependency]:
    found: list[Dependency] = []
    for match in ACTION_USES_RE.finditer(path.read_text(encoding="utf-8")):
        found.append(
            Dependency(
                name=match.group(1),
                version=match.group(2),
                ecosystem=Ecosystem.GITHUB_ACTIONS,
                kind=DependencyKind.CI,
                source=path,
            )
        )
    return found


def _python_dep(raw: str, path: Path, kind: DependencyKind = DependencyKind.APPLICATION) -> Dependency:
    match = PY_REQ_RE.match(raw)
    if not match:
        return Dependency(raw, None, Ecosystem.PYTHON, kind, path, raw)
    name, constraint = match.groups()
    return Dependency(name, _strip_constraint(constraint or ""), Ecosystem.PYTHON, kind, path, constraint)


def _strip_constraint(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None
    stripped = re.sub(r"^[\^~<>=!*\s]+", "", value)
    stripped = stripped.split(",", 1)[0].strip()
    return stripped or None
