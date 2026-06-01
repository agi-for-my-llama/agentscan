from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from .findings import SEVERITY_ORDER, Finding
from .rules import scan_json, scan_repo_metadata, scan_text


DEFAULT_EXCLUDES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}

TEXT_EXTENSIONS = {
    ".cfg",
    ".conf",
    ".env",
    ".ini",
    ".json",
    ".js",
    ".jsx",
    ".md",
    ".mjs",
    ".py",
    ".rb",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}


@dataclass
class ScanOptions:
    root: Path
    excludes: set[str] = field(default_factory=set)
    max_file_bytes: int = 1_000_000


def scan(options: ScanOptions) -> list[Finding]:
    root = options.root.resolve()
    findings: list[Finding] = []

    findings.extend(scan_repo_metadata(root))
    for path in _iter_files(root, options.excludes):
        if _skip_by_size(path, options.max_file_bytes) or not _looks_textual(path):
            continue
        display_path = _display_path(root, path)
        text = _read_text(path)
        if text is None:
            continue
        findings.extend(scan_text(path.relative_to(root), display_path, text))
        if path.suffix.lower() == ".json" or path.name.lower().endswith(".json"):
            findings.extend(scan_json(path.relative_to(root), display_path, text))

    return sorted(
        findings,
        key=lambda item: (-SEVERITY_ORDER[item.severity], item.path, item.line, item.rule_id),
    )


def _iter_files(root: Path, excludes: Iterable[str]) -> Iterator[Path]:
    excluded = {_normalize_path(item) for item in DEFAULT_EXCLUDES.union(excludes)}
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            children = list(current.iterdir())
        except OSError:
            continue

        for child in children:
            relative = _normalize_path(str(child.relative_to(root)))
            if _is_excluded(child.name, relative, excluded):
                continue
            if child.is_dir():
                stack.append(child)
            elif child.is_file():
                yield child


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            return path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            return None
    except OSError:
        return None


def _looks_textual(path: Path) -> bool:
    if path.name in {"AGENTS.md", "CLAUDE.md", "GEMINI.md", ".cursorrules", ".env"}:
        return True
    return path.suffix.lower() in TEXT_EXTENSIONS


def _skip_by_size(path: Path, max_file_bytes: int) -> bool:
    try:
        return path.stat().st_size > max_file_bytes
    except OSError:
        return True


def _display_path(root: Path, path: Path) -> str:
    return str(path.relative_to(root)).replace("\\", "/")


def _is_excluded(name: str, relative_path: str, excluded: set[str]) -> bool:
    if name in excluded or relative_path in excluded:
        return True
    return any(relative_path.startswith(f"{item}/") for item in excluded if "/" in item)


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/").strip("/")
