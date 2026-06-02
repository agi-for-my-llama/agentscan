from pathlib import Path

from depkit.cli import main


def test_plan_command_outputs_stages(capsys) -> None:
    root = Path(__file__).parents[1] / "examples" / "polyglot-app"

    assert main(["plan", str(root)]) == 0

    output = capsys.readouterr().out
    assert "Upgrade plan" in output
    assert "Stage 1: Tooling and CI" in output


def test_scan_command_outputs_parse_warnings(tmp_path: Path, capsys) -> None:
    (tmp_path / "package.json").write_text("[", encoding="utf-8")

    assert main(["scan", str(tmp_path)]) == 0

    output = capsys.readouterr().out
    assert "Warnings:" in output
    assert "package.json" in output


def test_missing_path_returns_usage_error(capsys) -> None:
    assert main(["scan", "definitely-missing-path"]) == 2

    err = capsys.readouterr().err
    assert "path does not exist" in err
