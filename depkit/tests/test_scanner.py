from pathlib import Path

from depkit.models import DependencyKind, Ecosystem
from depkit.scanner import scan, scan_with_warnings
from depkit.parsers import parse_dockerfile


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


def test_scan_parses_python_requirements_with_extras(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "fastapi[standard]==0.115.0\nrequests[socks]>=2.31\n",
        encoding="utf-8",
    )

    deps = scan(tmp_path)
    by_name = {dep.name: dep for dep in deps}

    assert by_name["fastapi"].version == "0.115.0"
    assert by_name["requests"].version == "2.31"


def test_scan_preserves_docker_registry_ports(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM registry.example.com:5000/team/app:1.2\nFROM alpine\n",
        encoding="utf-8",
    )

    deps = scan(tmp_path)
    by_name = {dep.name: dep.version for dep in deps}

    assert by_name["registry.example.com:5000/team/app"] == "1.2"
    assert by_name["alpine"] == "latest"


def test_scan_with_warnings_reports_invalid_manifests(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("[", encoding="utf-8")

    result = scan_with_warnings(tmp_path)

    assert result.dependencies == ()
    assert len(result.warnings) == 1
    assert result.warnings[0].source == tmp_path / "package.json"


def test_scan_skips_malformed_package_json_sections(tmp_path) -> None:
    (tmp_path / "package.json").write_text('{"dependencies": ["not", "an", "object"]}', encoding="utf-8")

    assert scan(tmp_path) == []


def test_scan_skips_malformed_pyproject_dependencies(tmp_path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = "fastapi"\n', encoding="utf-8")

    assert scan(tmp_path) == []


def test_dockerfile_parser_handles_registry_ports(tmp_path) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM registry.example.com:5000/team/app:1.2.3\n", encoding="utf-8")

    deps = parse_dockerfile(dockerfile)

    assert deps[0].name == "registry.example.com:5000/team/app"
    assert deps[0].version == "1.2.3"
