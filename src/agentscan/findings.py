from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Optional


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    path: str
    line: int
    message: str
    remediation: str
    evidence: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    def meets_threshold(self, threshold: str) -> bool:
        return SEVERITY_ORDER[self.severity] >= SEVERITY_ORDER[threshold]
