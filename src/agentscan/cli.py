from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .baseline import apply_baseline, finding_fingerprint, write_baseline
from .config import filter_findings, load_config
from .findings import SEVERITY_ORDER, Finding
from .scanner import ScanOptions, scan


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = Path(args.path)
    if args.version:
        print(__version__)
        return 0
    if not root.exists():
        parser.error(f"path does not exist: {root}")
    if not root.is_dir():
        parser.error(f"path is not a directory: {root}")
    if args.init_config:
        return _init_config(root)

    config = load_config(root.resolve(), args.config)
    for warning in config.warnings:
        print(f"agentscan: config warning: {warning}", file=sys.stderr)

    fail_on = args.fail_on or config.fail_on or "medium"
    max_file_bytes = args.max_file_bytes or config.max_file_bytes or 1_000_000
    excludes = set(config.exclude).union(args.exclude)

    try:
        findings = scan(
            ScanOptions(
                root=root,
                excludes=excludes,
                max_file_bytes=max_file_bytes,
            )
        )
        findings = filter_findings(findings, config)
        baseline_path = args.baseline or config.baseline
        if baseline_path:
            baseline_file = _resolve_scan_path(root, baseline_path)
            findings, baseline_warnings, baseline_ok = apply_baseline(findings, baseline_file)
            for warning in baseline_warnings:
                print(f"agentscan: baseline warning: {warning}", file=sys.stderr)
            if not baseline_ok:
                return 2
    except OSError as exc:
        print(f"agentscan: scan failed: {exc}", file=sys.stderr)
        return 2

    if args.update_baseline:
        baseline_output = _resolve_scan_path(root, args.update_baseline)
        write_baseline(baseline_output, findings)
        print(f"Wrote baseline with {len(findings)} finding(s): {baseline_output}")
        return 0

    if args.format == "json":
        _print_json(findings)
    elif args.format == "sarif":
        _print_sarif(findings)
    else:
        _print_text(findings)

    return 1 if any(item.meets_threshold(fail_on) for item in findings) else 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentscan",
        description="Scan repositories for AI agent, MCP, and launch-readiness risks.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository directory to scan.")
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print the AgentScan version.",
    )
    parser.add_argument(
        "--init-config",
        action="store_true",
        help="Create a starter .agentscan.json file.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Report format.",
    )
    parser.add_argument(
        "--fail-on",
        choices=sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get),
        default=None,
        help="Minimum severity that returns exit code 1.",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Directory or file name to skip. Can be passed more than once.",
    )
    parser.add_argument(
        "--max-file-bytes",
        type=int,
        default=None,
        help="Skip files larger than this many bytes.",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Path to a JSON config file. Defaults to .agentscan.json or agentscan.json.",
    )
    parser.add_argument(
        "--baseline",
        default=None,
        help="Ignore findings already present in a baseline file.",
    )
    parser.add_argument(
        "--update-baseline",
        default=None,
        help="Write the current findings to a baseline file and exit 0.",
    )
    return parser


def _init_config(root: Path) -> int:
    path = root / ".agentscan.json"
    if path.exists():
        print(f"Config already exists: {path}")
        return 0
    path.write_text(
        json.dumps(
            {
                "fail_on": "high",
                "$schema": "./.agentscan.schema.json",
                "exclude": ["dist", "vendor"],
                "ignore_rules": [],
                "ignore_paths": [],
                "severity_overrides": {},
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"Created {path}")
    return 0


def _resolve_scan_path(root: Path, path: str) -> Path:
    candidate = Path(path)
    return candidate if candidate.is_absolute() else root / candidate


def _print_json(findings: list[Finding]) -> None:
    print(json.dumps({"findings": [item.to_dict() for item in findings]}, indent=2))


def _print_sarif(findings: list[Finding]) -> None:
    rules = {}
    for item in findings:
        rules[item.rule_id] = {
            "id": item.rule_id,
            "name": item.rule_id,
            "shortDescription": {"text": item.message},
            "help": {"text": item.remediation},
            "helpUri": _rule_help_uri(item.rule_id),
            "defaultConfiguration": {"level": _sarif_level(item.severity)},
            "properties": {
                "tags": _rule_tags(item.rule_id),
                "precision": "high",
            },
        }

    results = []
    for item in findings:
        results.append(
            {
                "ruleId": item.rule_id,
                "level": _sarif_level(item.severity),
                "message": {"text": item.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": item.path},
                            "region": {"startLine": max(item.line, 1)},
                        }
                    }
                ],
                "partialFingerprints": {
                    "agentscan": finding_fingerprint(item),
                },
                "properties": {
                    "severity": item.severity,
                    "remediation": item.remediation,
                    "tags": _rule_tags(item.rule_id),
                    **({"evidence": item.evidence} if item.evidence else {}),
                },
            }
        )

    print(
        json.dumps(
            {
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "AgentScan",
                                "informationUri": "https://github.com/agi-for-my-llama/agentscan",
                                "rules": list(rules.values()),
                            }
                        },
                        "results": results,
                    }
                ],
            },
            indent=2,
        )
    )


def _print_text(findings: list[Finding]) -> None:
    if not findings:
        print("No findings.")
        return

    for item in findings:
        location = f"{item.path}:{item.line}" if item.line else item.path
        print(f"[{item.severity.upper()}] {item.rule_id} {location}")
        print(f"  {item.message}")
        if item.evidence:
            print(f"  Evidence: {item.evidence}")
        print(f"  Fix: {item.remediation}")
        print()


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _rule_help_uri(rule_id: str) -> str:
    section = rule_id.split(".")[0]
    if rule_id.startswith("mcp."):
        section = "mcpcommand"
    elif rule_id.startswith("agent.instructions."):
        section = "agentinstructions"
    elif rule_id.startswith("github.workflow."):
        section = "githubworkflow"
    elif rule_id.startswith("package.install-script"):
        section = "packageinstall-script"
    elif rule_id.startswith("oss.license-missing"):
        section = "osslicense-missing"
    return f"https://github.com/agi-for-my-llama/agentscan/blob/main/docs/rules.md#{section}"


def _rule_tags(rule_id: str) -> list[str]:
    tags = ["security"]
    if rule_id.startswith("secret."):
        tags.append("secrets")
    if rule_id.startswith("mcp."):
        tags.append("mcp")
    if rule_id.startswith("agent.instructions."):
        tags.append("agent-instructions")
    if rule_id.startswith("github.workflow."):
        tags.append("github-actions")
    if rule_id.startswith("package."):
        tags.append("supply-chain")
    if rule_id.startswith("oss."):
        tags.append("open-source")
    return tags


if __name__ == "__main__":
    raise SystemExit(main())
