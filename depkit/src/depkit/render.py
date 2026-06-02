from __future__ import annotations

from depkit.models import Dependency, Risk, ScanWarning, UpgradePlan


def render_scan(dependencies: list[Dependency]) -> str:
    if not dependencies:
        return "No dependency manifests found."
    lines = [f"Found {len(dependencies)} dependencies"]
    for dep in dependencies:
        version = dep.version or "unbounded"
        lines.append(f"- {dep.name}: {version} [{dep.ecosystem}/{dep.kind}] ({dep.source})")
    return "\n".join(lines)


def render_risks(risks: list[Risk]) -> str:
    if not risks:
        return "No dependency risks found."
    lines = ["Dependency risks"]
    for risk in risks:
        reasons = ", ".join(risk.reasons)
        version = risk.dependency.version or "unbounded"
        lines.append(f"- {risk.level}: {risk.dependency.name} {version} - {reasons}")
    return "\n".join(lines)


def render_plan(plan: UpgradePlan) -> str:
    if not plan.stages:
        return "No upgrade plan available."
    lines = [
        f"Upgrade plan for {plan.total_dependencies} dependencies",
        f"High-risk items: {plan.high_risk_count}",
        "",
    ]
    for index, stage in enumerate(plan.stages, start=1):
        lines.append(f"Stage {index}: {stage.title}")
        for risk in stage.risks:
            version = risk.dependency.version or "unbounded"
            reasons = ", ".join(risk.reasons)
            lines.append(f"- {risk.dependency.name}: {version} [{risk.level}; {reasons}]")
        lines.append("")
    return "\n".join(lines).rstrip()


def render_warnings(warnings: tuple[ScanWarning, ...]) -> str:
    if not warnings:
        return ""
    lines = ["Warnings:"]
    for warning in warnings:
        lines.append(f"- {warning.source}: {warning.message}")
    return "\n".join(lines)
