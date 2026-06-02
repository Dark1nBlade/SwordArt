from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Status(Enum):
    PERFORMED = "performed"
    FAILED = "failed"
    SKIPPED = "skipped"

class CISLevel(Enum):
    L1 = "L1"
    L2 = "L2"

@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    message: str = ""
    remediation: str = ""
    evidence: str = ""
    effort_estimate: str = "Low" # Low, Medium, High

@dataclass
class SecurityCheckResult:
    check_name: str
    status: Status
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    duration_seconds: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    error_message: Optional[str] = None
    skip_reason: Optional[str] = None
    severity: Severity = Severity.INFO

@dataclass
class AuditReport:
    check_results: List[SecurityCheckResult] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    version: str = "0.2.0"

    def get_risk_score(self) -> float:
        performed = [r for r in self.check_results if r.status == Status.PERFORMED]
        if not performed: return 0.0

        score = 0
        for r in performed:
            for f in r.findings:
                if f.severity == Severity.CRITICAL: score += 10
                elif f.severity == Severity.HIGH: score += 5
                elif f.severity == Severity.MEDIUM: score += 2
        return score

    def get_summary(self) -> Dict[str, int]:
        return {
            "performed": len([r for r in self.check_results if r.status == Status.PERFORMED]),
            "failed": len([r for r in self.check_results if r.status == Status.FAILED]),
            "skipped": len([r for r in self.check_results if r.status == Status.SKIPPED])
        }
