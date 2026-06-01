from abc import ABC, abstractmethod
from typing import Any, Dict
from fortigate_cis_audit.models import Finding, Status, Severity, CISLevel

class BaseCheck(ABC):
    check_id: str
    title: str
    level: CISLevel
    severity: Severity
    section: str
    remediation: str

    @abstractmethod
    def audit(self, config: Dict[str, Any]) -> Finding:
        pass

    def create_finding(self, status: Status, message: str) -> Finding:
        return Finding(
            check_id=self.check_id,
            title=self.title,
            level=self.level,
            severity=self.severity,
            status=status,
            message=message,
            remediation=self.remediation,
            section=self.section
        )
