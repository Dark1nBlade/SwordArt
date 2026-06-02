from typing import Dict, Any, List
from fortigate_cis_audit.engine.base_check import BaseCheck
from fortigate_cis_audit.models import SecurityCheckResult, Status, Severity, Finding

class DocumentConfig(BaseCheck):
    check_id = "SEC-01"
    title = "Document the Current Configuration"
    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        # Configuration is already parsed into 'config'
        hostname = config.get("config system global", {}).get("hostname", "Unknown")
        finding = Finding(
            check_id=self.check_id,
            title=self.title,
            severity=Severity.INFO,
            message=f"Configuration documented for host: {hostname}",
            evidence=str(config)[:200] + "..."
        )
        return self.create_result(Status.PERFORMED, findings=[finding])

class ReviewSecurityPolicies(BaseCheck):
    check_id = "SEC-02"
    title = "Review Security Policies"
    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        policies = config.get("config firewall policy", {}).get("edit", {})
        findings = []
        for p_id, p_data in policies.items():
            if p_data.get("action") == "accept":
                findings.append(Finding(
                    check_id=self.check_id,
                    title=f"Policy {p_id} review",
                    severity=Severity.LOW,
                    message=f"Accept policy {p_id} found from {p_data.get('srcaddr')} to {p_data.get('dstaddr')}"
                ))
        return self.create_result(Status.PERFORMED, findings=findings)

class CheckRuleShadowing(BaseCheck):
    check_id = "SEC-03"
    title = "Check for Rule Shadowing"
    remediation = "Reorder or consolidate policies to eliminate shadowed rules."
    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        # Simple heuristic: exact duplicates in src/dst/service
        policies = config.get("config firewall policy", {}).get("edit", {})
        seen = {}
        findings = []
        for p_id, p_data in policies.items():
            key = (p_data.get("srcaddr"), p_data.get("dstaddr"), p_data.get("service"))
            if key in seen:
                findings.append(Finding(
                    check_id=self.check_id,
                    title="Rule Shadowing Detected",
                    severity=Severity.MEDIUM,
                    message=f"Policy {p_id} might be shadowed by {seen[key]}",
                    remediation=self.remediation
                ))
            else:
                seen[key] = p_id
        return self.create_result(Status.PERFORMED, findings=findings)

class AuditNATRules(BaseCheck):
    check_id = "SEC-04"
    title = "Audit NAT Rules"
    remediation = "Ensure all NAT rules (VIPs) are necessary and limited to required services."
    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        vips = config.get("config firewall vip", {}).get("edit", {})
        findings = [Finding(
            check_id=self.check_id,
            title="NAT Rule Analysis",
            severity=Severity.INFO,
            message=f"Found {len(vips)} Virtual IPs configured.",
            remediation=self.remediation
        )]
        return self.create_result(Status.PERFORMED, findings=findings)

class ValidateVPN(BaseCheck):
    check_id = "SEC-05"
    title = "Validate VPN Configurations"
    remediation = "Upgrade to IKEv2: config vpn ipsec phase1-interface; edit <name>; set ike-version 2; next; end"
    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        vpns = config.get("config vpn ipsec phase1-interface", {}).get("edit", {})
        findings = []
        for name, data in vpns.items():
            if data.get("ike-version") == "1":
                findings.append(Finding(
                    check_id=self.check_id,
                    title="Weak IKE Version",
                    severity=Severity.HIGH,
                    message=f"VPN {name} uses IKEv1",
                    remediation=self.remediation
                ))
        return self.create_result(Status.PERFORMED, findings=findings)

class AssessLogging(BaseCheck):
    check_id = "SEC-06"
    title = "Assess Logging and Monitoring"
    remediation = "Enable remote syslog: config log syslogd setting; set status enable; end"
    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        syslog = config.get("config log syslogd setting", {})
        if syslog.get("status") != "enable":
            finding = Finding(
                check_id=self.check_id,
                title="Logging Disabled",
                severity=Severity.CRITICAL,
                message="Remote syslog is not enabled",
                remediation=self.remediation
            )
            return self.create_result(Status.PERFORMED, findings=[finding])
        return self.create_result(Status.PERFORMED)

class EvaluateAppLayer(BaseCheck):
    check_id = "SEC-07"
    title = "Evaluate Application Layer Inspection"
    remediation = "Enable Application Control on all relevant firewall policies: set appctrl <profile-name>"
    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        policies = config.get("config firewall policy", {}).get("edit", {})
        missing_app_ctrl = [p_id for p_id, p_data in policies.items() if not p_data.get("appctrl")]
        findings = []
        if missing_app_ctrl:
            findings.append(Finding(
                check_id=self.check_id,
                title="Missing Application Control",
                severity=Severity.MEDIUM,
                message=f"Policies {', '.join(missing_app_ctrl)} lack application control profiles.",
                remediation=self.remediation
            ))
        return self.create_result(Status.PERFORMED, findings=findings)

class CheckFirmware(BaseCheck):
    check_id = "SEC-08"
    title = "Check for Firmware and Patch Updates"
    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        # Version is usually in the header of the config, which our parser might skip
        # Let's assume we can find it in 'config system global' if set (it usually isn't)
        # For now, skip if not found
        return self.create_result(Status.SKIPPED, skip_reason="version_info_missing")

class PerformVulnScan(BaseCheck):
    check_id = "SEC-09"
    title = "Perform Vulnerability Scanning"
    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        return self.create_result(Status.SKIPPED, skip_reason="external_tool_required")

class ReviewChangeMgmt(BaseCheck):
    check_id = "SEC-10"
    title = "Review Change Management Procedures"
    remediation = "Enable revision backup on logout: config system global; set revision-backup-on-logout enable; end"
    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        # Checks if 'revision-backup-on-logout' is enabled
        global_cfg = config.get("config system global", {})
        if global_cfg.get("revision-backup-on-logout") != "enable":
             return self.create_result(Status.PERFORMED, findings=[Finding(
                 check_id=self.check_id,
                 title="Change Tracking Weakness",
                 severity=Severity.LOW,
                 message="Revision backup on logout is disabled.",
                 remediation=self.remediation
             )])
        return self.create_result(Status.PERFORMED)

class TestFirewallRules(BaseCheck):
    check_id = "SEC-11"
    title = "Test Firewall Rules"
    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        return self.create_result(Status.SKIPPED, skip_reason="manual_testing_required")

class CreateAuditReport(BaseCheck):
    check_id = "SEC-12"
    title = "Create an Audit Report"
    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        # This is a meta-check, we just mark it performed
        return self.create_result(Status.PERFORMED)

class ImplementRemediation(BaseCheck):
    check_id = "SEC-13"
    title = "Implement Remediation Actions"
    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        return self.create_result(Status.SKIPPED, skip_reason="manual_action_required")

class CheckIPSConfigured(BaseCheck):
    check_id = "SEC-14"
    title = "Verify IPS is enabled on policies"
    remediation = "Enable IPS profile on firewall policies, especially those facing the internet: set ips-sensor <profile-name>"
    wan_interfaces: List[str] = []

    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        policies = config.get("config firewall policy", {}).get("edit", {})
        findings = []

        for p_id, p_data in policies.items():
            ips_enabled = p_data.get("ips-sensor")
            srcintf = p_data.get("srcintf")
            dstintf = p_data.get("dstintf")

            is_wan_policy = False
            if self.wan_interfaces:
                if srcintf in self.wan_interfaces or dstintf in self.wan_interfaces:
                    is_wan_policy = True

            if not ips_enabled:
                severity = Severity.HIGH if is_wan_policy else Severity.MEDIUM
                findings.append(Finding(
                    check_id=self.check_id,
                    title="IPS Not Enabled",
                    severity=severity,
                    message=f"Policy {p_id} ({srcintf} -> {dstintf}) does not have IPS enabled.",
                    remediation=self.remediation
                ))

        if not findings:
            return self.create_result(Status.PERFORMED)

        return self.create_result(Status.PERFORMED, findings=findings)
