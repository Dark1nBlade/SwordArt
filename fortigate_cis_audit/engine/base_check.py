from abc import ABC, abstractmethod
from typing import Any, Dict, List
from fortigate_cis_audit.models import Finding, Status, Severity, CISLevel, SecurityCheckResult

class BaseCheck(ABC):
    check_id: str
    title: str
    level: CISLevel = CISLevel.L1 # Default for CIS checks
    severity: Severity = Severity.INFO
    section: str = ""
    remediation: str = ""
    mitre_techniques: List[str] = []
    nist_csf: List[str] = []
    cis_v8: List[str] = []
    iso27001: List[str] = []

    @abstractmethod
    def audit(self, config: Dict[str, Any]) -> Any:
        pass

    def create_finding(self, status: Status, message: str) -> Finding:
        return Finding(
            check_id=self.check_id,
            title=self.title,
            level=getattr(self, 'level', CISLevel.L1),
            severity=self.severity,
            status=status,
            message=message,
            remediation=self.remediation,
            section=getattr(self, 'section', ""),
            mitre_techniques=self.mitre_techniques,
            nist_csf=self.nist_csf,
            cis_v8=self.cis_v8,
            iso27001=self.iso27001
        )

    def create_result(self, status: Status, findings=None, error_message=None, skip_reason=None) -> SecurityCheckResult:
        return SecurityCheckResult(
            check_name=self.title,
            status=status,
            findings=findings or [],
            error_message=error_message,
            skip_reason=skip_reason,
            severity=self.severity
        )
