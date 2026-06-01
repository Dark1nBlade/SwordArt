from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any

class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

class Status(Enum):
    PASS = "Pass"
    FAIL = "Fail"
    WARN = "Warn"
    SKIP = "Skip"

class CISLevel(Enum):
    L1 = "L1"
    L2 = "L2"

@dataclass
class Finding:
    check_id: str
    title: str
    level: CISLevel
    severity: Severity
    status: Status
    message: str = ""
    remediation: str = ""
    section: str = ""

@dataclass
class AuditReport:
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_score(self) -> float:
        total = len([f for f in self.findings if f.status != Status.SKIP])
        if total == 0:
            return 0.0
        passed = len([f for f in self.findings if f.status == Status.PASS])
        return (passed / total) * 100
