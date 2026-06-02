from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class Ecosystem(StrEnum):
    DOCKER = "docker"
    GITHUB_ACTIONS = "github-actions"
    GO = "go"
    NODE = "node"
    PYTHON = "python"


class DependencyKind(StrEnum):
    APPLICATION = "application"
    CI = "ci"
    DEV = "dev"
    RUNTIME = "runtime"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str | None
    ecosystem: Ecosystem
    kind: DependencyKind
    source: Path
    constraint: str | None = None


@dataclass(frozen=True)
class Risk:
    dependency: Dependency
    level: RiskLevel
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class PlanStage:
    title: str
    risks: tuple[Risk, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class UpgradePlan:
    stages: tuple[PlanStage, ...]
    total_dependencies: int
    high_risk_count: int
