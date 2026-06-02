from pathlib import Path

from depkit.cli import main


def test_plan_command_outputs_stages(capsys) -> None:
    root = Path(__file__).parents[1] / "examples" / "polyglot-app"

    assert main(["plan", str(root)]) == 0

    output = capsys.readouterr().out
    assert "Upgrade plan" in output
    assert "Stage 1: Tooling and CI" in output
