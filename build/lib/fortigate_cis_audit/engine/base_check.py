from abc import ABC, abstractmethod
from typing import Any, Dict
from fortigate_cis_audit.models import SecurityCheckResult, Status, Severity, Finding

class BaseCheck(ABC):
    check_id: str
    title: str
    severity: Severity = Severity.INFO

    @abstractmethod
    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        pass

    def create_result(self, status: Status, findings=None, error_message=None, skip_reason=None) -> SecurityCheckResult:
        return SecurityCheckResult(
            check_name=self.title,
            status=status,
            findings=findings or [],
            error_message=error_message,
            skip_reason=skip_reason,
            severity=self.severity
        )
