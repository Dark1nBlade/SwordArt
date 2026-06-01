from fortigate_cis_audit.engine.base_check import BaseCheck
from fortigate_cis_audit.models import Status, Severity, CISLevel
from typing import Dict, Any

class CheckSyslogConfigured(BaseCheck):
    check_id = "CIS-3.1"
    title = "Confirm syslog server is configured"
    level = CISLevel.L1
    severity = Severity.MEDIUM
    section = "3. Logging & Monitoring"
    remediation = "config log syslogd setting\n  set status enable\n  set server <ip>\nend"

    def audit(self, config: Dict[str, Any]) -> Any:
        log_cfg = config.get("config log syslogd setting", {})
        status = log_cfg.get("status")
        server = log_cfg.get("server")
        if status == "enable" and server:
            return self.create_finding(Status.PASS, f"Syslog is enabled and server is set to {server}.")
        else:
            return self.create_finding(Status.FAIL, "Syslog is not enabled or server is not set.")
