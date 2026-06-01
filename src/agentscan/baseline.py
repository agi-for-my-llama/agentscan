from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .findings import Finding


BASELINE_VERSION = 1


def finding_fingerprint(finding: Finding) -> str:
    payload = "|".join(
        [
            finding.rule_id,
            finding.path,
            str(finding.line),
            finding.evidence or finding.message,
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def write_baseline(path: Path, findings: list[Finding]) -> None:
    path.write_text(
        json.dumps(
            {
                "version": BASELINE_VERSION,
                "findings": [
                    {
                        "fingerprint": finding_fingerprint(finding),
                        "rule_id": finding.rule_id,
                        "severity": finding.severity,
                        "path": finding.path,
                        "line": finding.line,
                        "message": finding.message,
                    }
                    for finding in findings
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def apply_baseline(findings: list[Finding], path: Path) -> tuple[list[Finding], list[str]]:
    warnings: list[str] = []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return findings, [f"Could not read baseline: {exc}"]
    except json.JSONDecodeError as exc:
        return findings, [f"Could not parse baseline JSON: {exc}"]

    fingerprints = _baseline_fingerprints(raw)
    if fingerprints is None:
        return findings, ["Ignoring invalid baseline format."]

    return [item for item in findings if finding_fingerprint(item) not in fingerprints], warnings


def _baseline_fingerprints(raw: Any) -> set[str] | None:
    if not isinstance(raw, dict):
        return None
    findings = raw.get("findings")
    if not isinstance(findings, list):
        return None

    fingerprints: set[str] = set()
    for item in findings:
        if not isinstance(item, dict):
            continue
        fingerprint = item.get("fingerprint")
        if isinstance(fingerprint, str) and fingerprint:
            fingerprints.add(fingerprint)
    return fingerprints
