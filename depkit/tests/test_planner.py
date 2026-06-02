from pathlib import Path

from depkit.models import RiskLevel
from depkit.planner import assess, build_plan
from depkit.scanner import scan


def test_assess_marks_runtime_and_frameworks_high_risk() -> None:
    root = Path(__file__).parents[1] / "examples" / "polyglot-app"

    risks = assess(scan(root))
    high_risk_names = {risk.dependency.name for risk in risks if risk.level is RiskLevel.HIGH}

    assert "node" in high_risk_names
    assert "python" in high_risk_names
    assert "next" in high_risk_names


def test_build_plan_groups_work_into_stages() -> None:
    root = Path(__file__).parents[1] / "examples" / "polyglot-app"

    plan = build_plan(scan(root))
    titles = [stage.title for stage in plan.stages]

    assert titles[0] == "Tooling and CI"
    assert "Runtime foundations" in titles
    assert "Frameworks and platform packages" in titles
    assert plan.high_risk_count > 0
