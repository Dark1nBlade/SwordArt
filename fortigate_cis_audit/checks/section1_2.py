from fortigate_cis_audit.engine.base_check import BaseCheck
from fortigate_cis_audit.models import Status, Severity, CISLevel
from typing import Dict, Any

class CheckHTTPSOnly(BaseCheck):
    check_id = "CIS-1.1"
    title = "Ensure HTTPS-only admin access"
    level = CISLevel.L1
    severity = Severity.HIGH
    section = "1. Management Access"
    remediation = "config system global\n  set admin-https-redirect enable\nend"

    def audit(self, config: Dict[str, Any]) -> Any:
        global_cfg = config.get("config system global", {})
        redirect = global_cfg.get("admin-https-redirect")
        if redirect == "enable":
            return self.create_finding(Status.PASS, "HTTPS redirect is enabled.")
        else:
            return self.create_finding(Status.FAIL, "HTTPS redirect is not enabled.")

class CheckIdleTimeout(BaseCheck):
    check_id = "CIS-1.4"
    title = "Check idle session timeout <= 5 minutes"
    level = CISLevel.L1
    severity = Severity.MEDIUM
    section = "1. Management Access"
    remediation = "config system global\n  set admintimeout 5\nend"

    def audit(self, config: Dict[str, Any]) -> Any:
        global_cfg = config.get("config system global", {})
        timeout = global_cfg.get("admintimeout")
        if timeout and int(timeout) <= 5:
            return self.create_finding(Status.PASS, f"Idle timeout is set to {timeout} minutes.")
        else:
            return self.create_finding(Status.FAIL, f"Idle timeout is {timeout}, should be 5 or less.")

class CheckSSHv2Only(BaseCheck):
    check_id = "CIS-2.3"
    title = "Ensure SSH v2 only"
    level = CISLevel.L1
    severity = Severity.MEDIUM
    section = "2. Authentication & MFA"
    remediation = "config system global\n  set ssh-protocol-version v2\nend"

    def audit(self, config: Dict[str, Any]) -> Any:
        global_cfg = config.get("config system global", {})
        version = global_cfg.get("ssh-protocol-version")
        if version == "v2":
            return self.create_finding(Status.PASS, "SSH protocol version set to v2.")
        else:
            return self.create_finding(Status.FAIL, "SSH protocol version is not set to v2.")
