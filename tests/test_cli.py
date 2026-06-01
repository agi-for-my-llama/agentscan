from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from agentscan.cli import main


class CliTests(unittest.TestCase):
    def test_json_format_outputs_findings_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("# Example\n", encoding="utf-8")
            stdout = StringIO()

            with redirect_stdout(stdout):
                exit_code = main([str(root), "--format", "json", "--fail-on", "critical"])

        self.assertEqual(exit_code, 0)
        self.assertIn("findings", json.loads(stdout.getvalue()))

    def test_sarif_format_outputs_sarif_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("# Example\n", encoding="utf-8")
            stdout = StringIO()

            with redirect_stdout(stdout):
                exit_code = main([str(root), "--format", "sarif", "--fail-on", "critical"])

        report = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(report["version"], "2.1.0")

    def test_config_can_ignore_rule_and_set_fail_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("# Example\n", encoding="utf-8")
            (root / ".agentscan.json").write_text(
                json.dumps({"fail_on": "medium", "ignore_rules": ["oss.license-missing"]}),
                encoding="utf-8",
            )
            stdout = StringIO()

            with redirect_stdout(stdout):
                exit_code = main([str(root), "--format", "json"])

        report = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(report["findings"], [])

    def test_init_config_creates_starter_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stdout = StringIO()

            with redirect_stdout(stdout):
                exit_code = main([str(root), "--init-config"])

            config = json.loads((root / ".agentscan.json").read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(config["fail_on"], "high")
        self.assertEqual(config["$schema"], "./.agentscan.schema.json")

    def test_config_baseline_ignores_existing_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline_path = root / "agentscan-baseline.json"
            (root / "README.md").write_text("# Example\n", encoding="utf-8")
            with redirect_stdout(StringIO()):
                main([str(root), "--update-baseline", str(baseline_path)])
            (root / ".agentscan.json").write_text(
                json.dumps({"fail_on": "medium", "baseline": "agentscan-baseline.json"}),
                encoding="utf-8",
            )
            stdout = StringIO()

            with redirect_stdout(stdout):
                exit_code = main([str(root), "--format", "json"])

        report = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(report["findings"], [])

    def test_version_prints_package_version(self) -> None:
        stdout = StringIO()

        with redirect_stdout(stdout):
            exit_code = main(["--version"])

        self.assertEqual(exit_code, 0)
        self.assertRegex(stdout.getvalue().strip(), r"^\d+\.\d+\.\d+")

    def test_update_baseline_writes_findings_and_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline_path = root / "agentscan-baseline.json"
            (root / "README.md").write_text("# Example\n", encoding="utf-8")
            stdout = StringIO()

            with redirect_stdout(stdout):
                exit_code = main([str(root), "--update-baseline", str(baseline_path)])

            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(baseline["version"], 1)
        self.assertEqual(baseline["findings"][0]["rule_id"], "oss.license-missing")

    def test_baseline_ignores_existing_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline_path = root / "agentscan-baseline.json"
            (root / "README.md").write_text("# Example\n", encoding="utf-8")
            with redirect_stdout(StringIO()):
                main([str(root), "--update-baseline", str(baseline_path)])
            stdout = StringIO()

            with redirect_stdout(stdout):
                exit_code = main(
                    [
                        str(root),
                        "--baseline",
                        str(baseline_path),
                        "--format",
                        "json",
                        "--fail-on",
                        "medium",
                    ]
                )

        report = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(report["findings"], [])


if __name__ == "__main__":
    unittest.main()
