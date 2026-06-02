from __future__ import annotations

import re
from collections import defaultdict

from depkit.models import Dependency, DependencyKind, Ecosystem, PlanStage, Risk, RiskLevel, UpgradePlan


FOUNDATION_NAMES = {
    "go",
    "node",
    "python",
    "ruby",
    "ubuntu",
    "debian",
    "alpine",
}

FRAMEWORK_NAMES = {
    "django",
    "fastapi",
    "next",
    "next.js",
    "react",
    "spring-boot",
    "vue",
}


def assess(dependencies: list[Dependency]) -> list[Risk]:
    grouped = defaultdict(list)
    for dep in dependencies:
        grouped[(dep.ecosystem, dep.name)].append(dep)

    risks: list[Risk] = []
    for dep in dependencies:
        reasons: list[str] = []
        level = RiskLevel.LOW

        if dep.kind is DependencyKind.RUNTIME or dep.name.lower() in FOUNDATION_NAMES:
            level = RiskLevel.HIGH
            reasons.append("runtime foundation")
        elif dep.name.lower() in FRAMEWORK_NAMES:
            level = RiskLevel.HIGH
            reasons.append("application framework")
        elif dep.kind is DependencyKind.CI:
            level = RiskLevel.MEDIUM
            reasons.append("CI workflow dependency")
        elif dep.kind is DependencyKind.DEV:
            reasons.append("development-only dependency")
        else:
            reasons.append("application dependency")

        if dep.version in {None, "latest", "*"}:
            level = _max_level(level, RiskLevel.HIGH)
            reasons.append("unbounded version")

        if dep.constraint and any(marker in dep.constraint for marker in ("<", "~=", "^")):
            level = _max_level(level, RiskLevel.MEDIUM)
            reasons.append("range constraint")

        if _major(dep.version) == 0:
            level = _max_level(level, RiskLevel.MEDIUM)
            reasons.append("pre-1.0 package")

        if len(grouped[(dep.ecosystem, dep.name)]) > 1:
            level = _max_level(level, RiskLevel.MEDIUM)
            reasons.append("declared in multiple files")

        risks.append(Risk(dep, level, tuple(dict.fromkeys(reasons))))
    return sorted(risks, key=lambda risk: (_stage_rank(risk), str(risk.dependency.source), risk.dependency.name))


def build_plan(dependencies: list[Dependency]) -> UpgradePlan:
    risks = assess(dependencies)
    ci = tuple(risk for risk in risks if risk.dependency.kind is DependencyKind.CI)
    runtime = tuple(risk for risk in risks if _is_runtime(risk.dependency))
    frameworks = tuple(risk for risk in risks if risk.dependency.name.lower() in FRAMEWORK_NAMES)
    packages = tuple(
        risk
        for risk in risks
        if risk not in ci and risk not in runtime and risk not in frameworks
    )

    stages = tuple(
        stage
        for stage in (
            PlanStage("Tooling and CI", ci),
            PlanStage("Runtime foundations", runtime),
            PlanStage("Frameworks and platform packages", frameworks),
            PlanStage("Application packages", packages),
        )
        if stage.risks
    )
    return UpgradePlan(
        stages=stages,
        total_dependencies=len(dependencies),
        high_risk_count=sum(1 for risk in risks if risk.level is RiskLevel.HIGH),
    )


def _is_runtime(dep: Dependency) -> bool:
    return dep.kind is DependencyKind.RUNTIME or dep.ecosystem is Ecosystem.DOCKER or dep.name.lower() in FOUNDATION_NAMES


def _stage_rank(risk: Risk) -> int:
    dep = risk.dependency
    if dep.kind is DependencyKind.CI:
        return 0
    if _is_runtime(dep):
        return 1
    if dep.name.lower() in FRAMEWORK_NAMES:
        return 2
    return 3


def _major(version: str | None) -> int | None:
    if not version:
        return None
    match = re.search(r"(\d+)", version)
    return int(match.group(1)) if match else None


def _max_level(left: RiskLevel, right: RiskLevel) -> RiskLevel:
    order = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2}
    return left if order[left] >= order[right] else right
