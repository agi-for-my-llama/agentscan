from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .findings import SEVERITY_ORDER, Finding


DEFAULT_CONFIG_NAMES = (".agentscan.json", "agentscan.json")


@dataclass(frozen=True)
class AgentScanConfig:
    exclude: tuple[str, ...] = ()
    ignore_rules: tuple[str, ...] = ()
    ignore_paths: tuple[str, ...] = ()
    fail_on: str | None = None
    max_file_bytes: int | None = None
    raw_path: Path | None = None
    warnings: tuple[str, ...] = field(default_factory=tuple)


def load_config(root: Path, explicit_path: str | None = None) -> AgentScanConfig:
    path = _resolve_config_path(root, explicit_path)
    if path is None:
        return AgentScanConfig()

    warnings: list[str] = []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return AgentScanConfig(raw_path=path, warnings=(f"Could not read config: {exc}",))
    except json.JSONDecodeError as exc:
        return AgentScanConfig(raw_path=path, warnings=(f"Could not parse config JSON: {exc}",))

    if not isinstance(raw, dict):
        return AgentScanConfig(raw_path=path, warnings=("Config root must be a JSON object.",))

    fail_on = _optional_str(raw.get("fail_on"))
    if fail_on is not None and fail_on not in SEVERITY_ORDER:
        warnings.append(f"Ignoring invalid fail_on value: {fail_on}")
        fail_on = None

    max_file_bytes = raw.get("max_file_bytes")
    if not isinstance(max_file_bytes, int) or max_file_bytes <= 0:
        if max_file_bytes is not None:
            warnings.append("Ignoring invalid max_file_bytes value.")
        max_file_bytes = None

    return AgentScanConfig(
        exclude=tuple(_string_list(raw.get("exclude"))),
        ignore_rules=tuple(_string_list(raw.get("ignore_rules"))),
        ignore_paths=tuple(_normalize_path(item) for item in _string_list(raw.get("ignore_paths"))),
        fail_on=fail_on,
        max_file_bytes=max_file_bytes,
        raw_path=path,
        warnings=tuple(warnings),
    )


def filter_findings(findings: list[Finding], config: AgentScanConfig) -> list[Finding]:
    if not config.ignore_rules and not config.ignore_paths:
        return findings

    return [
        finding
        for finding in findings
        if not _ignored_by_rule(finding.rule_id, config.ignore_rules)
        and not _ignored_by_path(finding.path, config.ignore_paths)
    ]


def _resolve_config_path(root: Path, explicit_path: str | None) -> Path | None:
    if explicit_path:
        path = Path(explicit_path)
        return path if path.is_absolute() else root / path

    for name in DEFAULT_CONFIG_NAMES:
        path = root / name
        if path.exists():
            return path
    return None


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item.strip()]


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _ignored_by_rule(rule_id: str, ignore_rules: tuple[str, ...]) -> bool:
    for pattern in ignore_rules:
        if pattern.endswith("*") and rule_id.startswith(pattern[:-1]):
            return True
        if rule_id == pattern:
            return True
    return False


def _ignored_by_path(path: str, ignore_paths: tuple[str, ...]) -> bool:
    normalized = _normalize_path(path)
    return any(normalized == item or normalized.startswith(f"{item}/") for item in ignore_paths)


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/").strip("/")
