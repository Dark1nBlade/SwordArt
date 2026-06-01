from typing import List, Dict, Any
from fortigate_cis_audit.models import AuditReport, Finding
from fortigate_cis_audit.engine.base_check import BaseCheck

class AuditEngine:
    def __init__(self, config: Dict[str, Any], checks: List[BaseCheck]):
        self.config = config
        self.checks = checks

    def run(self) -> AuditReport:
        report = AuditReport()
        for check in self.checks:
            try:
                finding = check.audit(self.config)
                report.findings.append(finding)
            except Exception as e:
                # Should probably log this or create a SKIP finding
                pass
        return report
