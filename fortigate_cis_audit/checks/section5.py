from fortigate_cis_audit.engine.base_check import BaseCheck
from fortigate_cis_audit.models import Status, Severity, CISLevel
from typing import Dict, Any

class CheckAnyAnyPolicy(BaseCheck):
    check_id = "CIS-5.1"
    title = "Flag any permit any any policies"
    level = CISLevel.L1
    severity = Severity.CRITICAL
    section = "5. Firewall Policies"
    remediation = "Review policy and restrict source, destination, and services."
    mitre_techniques = ["T1190", "T1071"]
    nist_csf = ["PR.AC-04", "PR.PS-04"]
    cis_v8 = ["4.1", "4.4", "4.5"]
    iso27001 = ["A.8.1", "A.8.3"]

    def audit(self, config: Dict[str, Any]) -> Any:
        policy_cfg = config.get("config firewall policy", {}).get("edit", {})
        findings = []
        for p_id, p_data in policy_cfg.items():
            srcaddr = p_data.get("srcaddr")
            dstaddr = p_data.get("dstaddr")
            service = p_data.get("service")
            action = p_data.get("action")

            if action == "accept" and srcaddr == "all" and dstaddr == "all" and service == "ALL":
                findings.append(p_id)

        if findings:
            return self.create_finding(Status.FAIL, f"Found permit any any in policies: {', '.join(findings)}")
        else:
            return self.create_finding(Status.PASS, "No permit any any policies found.")
