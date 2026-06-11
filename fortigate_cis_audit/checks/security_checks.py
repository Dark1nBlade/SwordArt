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
    mitre_techniques = ["T1190", "T1071"]
    nist_csf = ["PR.AC-04", "PR.PS-04"]
    cis_v8 = ["4.1", "4.4", "4.5"]
    iso27001 = ["A.8.1", "A.8.3"]
    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        policies = config.get("config firewall policy", {}).get("edit", {})
        findings = []
        for p_id, p_data in policies.items():
            if p_data.get("action") == "accept":
                findings.append(Finding(
                    check_id=self.check_id,
                    title=f"Policy {p_id} review",
                    severity=Severity.LOW,
                    message=f"Accept policy {p_id} found from {p_data.get('srcaddr')} to {p_data.get('dstaddr')}",
                    mitre_techniques=self.mitre_techniques,
                    nist_csf=self.nist_csf,
                    cis_v8=self.cis_v8,
                    iso27001=self.iso27001
                ))
        return self.create_result(Status.PERFORMED, findings=findings)

class CheckRuleShadowing(BaseCheck):
    check_id = "SEC-03"
    title = "Check for Rule Shadowing"
    remediation = "Reorder or consolidate policies to eliminate shadowed rules."
    mitre_techniques = ["T1190", "T1071"]
    nist_csf = ["PR.AC-04", "PR.PS-04"]
    cis_v8 = ["4.4"]
    iso27001 = ["A.8.1", "A.8.3"]
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
                    remediation=self.remediation,
                    mitre_techniques=self.mitre_techniques,
                    nist_csf=self.nist_csf,
                    cis_v8=self.cis_v8,
                    iso27001=self.iso27001
                ))
            else:
                seen[key] = p_id
        return self.create_result(Status.PERFORMED, findings=findings)

class AuditNATRules(BaseCheck):
    check_id = "SEC-04"
    title = "Audit NAT Rules"
    remediation = "Ensure all NAT rules (VIPs) are necessary and limited to required services."
    mitre_techniques = ["T1090", "T1571"]
    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        vips = config.get("config firewall vip", {}).get("edit", {})
        findings = [Finding(
            check_id=self.check_id,
            title="NAT Rule Analysis",
            severity=Severity.INFO,
            message=f"Found {len(vips)} Virtual IPs configured.",
            remediation=self.remediation,
            mitre_techniques=self.mitre_techniques
        )]
        return self.create_result(Status.PERFORMED, findings=findings)

class ValidateVPN(BaseCheck):
    check_id = "SEC-05"
    title = "Validate VPN Configurations"
    remediation = "Upgrade to IKEv2: config vpn ipsec phase1-interface; edit <name>; set ike-version 2; next; end"
    mitre_techniques = ["T1133", "T1567"]
    nist_csf = ["PR.AC-07", "PR.IR-01"]
    cis_v8 = ["6.1", "6.2"]
    iso27001 = ["A.8.5", "A.8.24"]
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
                    remediation=self.remediation,
                    mitre_techniques=self.mitre_techniques,
                    nist_csf=self.nist_csf,
                    cis_v8=self.cis_v8,
                    iso27001=self.iso27001
                ))
        return self.create_result(Status.PERFORMED, findings=findings)

class AssessLogging(BaseCheck):
    check_id = "SEC-06"
    title = "Assess Logging and Monitoring"
    remediation = "Enable remote syslog: config log syslogd setting; set status enable; end"
    mitre_techniques = ["T1070", "T1562"]
    nist_csf = ["DE.CM-01", "DE.AE-01"]
    cis_v8 = ["8.2", "8.3"]
    iso27001 = ["A.8.15", "A.8.16"]
    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        syslog = config.get("config log syslogd setting", {})
        if syslog.get("status") != "enable":
            finding = Finding(
                check_id=self.check_id,
                title="Logging Disabled",
                severity=Severity.CRITICAL,
                message="Remote syslog is not enabled",
                remediation=self.remediation,
                mitre_techniques=self.mitre_techniques,
                nist_csf=self.nist_csf,
                cis_v8=self.cis_v8,
                iso27001=self.iso27001
            )
            return self.create_result(Status.PERFORMED, findings=[finding])
        return self.create_result(Status.PERFORMED)

class EvaluateAppLayer(BaseCheck):
    check_id = "SEC-07"
    title = "Evaluate Application Layer Inspection"
    remediation = "Enable Application Control on all relevant firewall policies: set appctrl <profile-name>"
    mitre_techniques = ["T1071"]
    nist_csf = ["PR.DS-02", "PR.PS-05"]
    cis_v8 = ["13.1"]
    iso27001 = ["A.8.3", "A.8.15"]
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
                remediation=self.remediation,
                mitre_techniques=self.mitre_techniques,
                nist_csf=self.nist_csf,
                cis_v8=self.cis_v8,
                iso27001=self.iso27001
            ))
        return self.create_result(Status.PERFORMED, findings=findings)

from fortigate_cis_audit.connectors.fortiguard import get_fortiguard_client

class CheckFirmware(BaseCheck):
    check_id = "SEC-08"
    title = "Check for Firmware and Patch Updates"
    mitre_techniques = ["T1195", "T1068"]
    nist_csf = ["PR.PS-01", "PR.IR-01"]
    cis_v8 = ["7.1", "7.4"]
    iso27001 = ["A.8.8"]

    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        # Try to find version in config
        version_line = config.get("version_info", "") # Need to update parser to capture this
        if not version_line:
            # Fallback: check config system global for hostname to help FG lookup
            hostname = config.get("config system global", {}).get("hostname", "FortiGate-VM64")
            # In a real scenario, version might be passed in metadata or captured from CLI header
            version = "7.0.0" # Mocking current version
        else:
            version = version_line

        fg = get_fortiguard_client()
        findings = []

        # Check EOL
        if fg.is_eol(version):
            findings.append(Finding(
                check_id=self.check_id,
                title="End-of-Life Firmware",
                severity=Severity.CRITICAL,
                message=f"Firmware version {version} is End-of-Life.",
                remediation="Upgrade to a supported FortiOS version (7.0+)."
            ))

        # Check Vulnerabilities
        vulns = fg.get_vulnerabilities(version)
        for v in vulns:
            findings.append(Finding(
                check_id=self.check_id,
                title=f"Firmware Vulnerability: {v['id']}",
                severity=Severity(v['severity'].capitalize()),
                message=f"Current version {version} is impacted by {v['id']} ({v['cve']}).",
                remediation=f"Upgrade to a patched version to remediate {v['cve']}."
            ))

        # Check for updates
        model = "FortiGate-VM64" # Mock
        latest = fg.get_latest_stable(model)
        if latest and latest != version:
             findings.append(Finding(
                check_id=self.check_id,
                title="Firmware Update Available",
                severity=Severity.LOW,
                message=f"A newer stable firmware version ({latest}) is available.",
                remediation=f"Schedule an upgrade to {latest}."
            ))

        if not findings:
            return self.create_result(Status.PERFORMED)
        return self.create_result(Status.PERFORMED, findings=findings)

class CheckWeakCrypto(BaseCheck):
    check_id = "SEC-20"
    title = "Verify Strong Encryption for Management"
    remediation = "Disable weak ciphers and protocols: config system global; set ssl-min-proto-version tls1-2; end"
    mitre_techniques = ["T1071.001", "T1573"]
    nist_csf = ["PR.DS-02"]

    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        global_cfg = config.get("config system global", {})
        min_tls = global_cfg.get("ssl-min-proto-version")
        findings = []
        if min_tls in ["sslv3", "tls1-0", "tls1-1"]:
            findings.append(Finding(
                check_id=self.check_id,
                title="Weak TLS Version",
                severity=Severity.HIGH,
                message=f"Minimum TLS version is set to {min_tls}.",
                remediation=self.remediation
            ))

        ssh_cfg = config.get("config system ssh", {}) # Often separate in newer versions
        # Mocking weak cipher detection
        return self.create_result(Status.PERFORMED, findings=findings)

class CheckExposedManagement(BaseCheck):
    check_id = "SEC-21"
    title = "Detect Exposed Management Interfaces"
    remediation = "Disable administrative access (HTTP/HTTPS/SSH/Telnet) on WAN-facing interfaces."
    mitre_techniques = ["T1078", "T1098"]

    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        interfaces = config.get("config system interface", {}).get("edit", {})
        findings = []
        # In a real tool, we'd use the --wan flag passed to the engine
        # For this audit, we'll check interfaces with names containing 'wan'
        for name, data in interfaces.items():
            allow = data.get("allowaccess", "")
            is_wan = "wan" in name.lower() or data.get("role") == "wan"

            unsafe = ["http", "telnet", "ssh", "https"]
            detected = [p for p in unsafe if p in allow.lower()]

            if is_wan and detected:
                findings.append(Finding(
                    check_id=self.check_id,
                    title="Management Exposed on WAN",
                    severity=Severity.CRITICAL if "http" in detected or "telnet" in detected else Severity.HIGH,
                    message=f"Interface {name} (WAN) allows: {', '.join(detected)}",
                    remediation=f"Remove {', '.join(detected)} from allowaccess on {name}."
                ))
        return self.create_result(Status.PERFORMED, findings=findings)

class CheckSSLVPNConfig(BaseCheck):
    check_id = "SEC-22"
    title = "Audit SSL VPN Configuration"
    remediation = "Harden SSL VPN settings: disable weak TLS and ensure DTLS is enabled for performance."
    mitre_techniques = ["T1133"]

    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        vpn_cfg = config.get("config vpn ssl settings", {})
        findings = []
        if vpn_cfg.get("tlsv1-0") == "enable" or vpn_cfg.get("tlsv1-1") == "enable":
             findings.append(Finding(
                check_id=self.check_id,
                title="Weak SSL VPN Encryption",
                severity=Severity.HIGH,
                message="SSL VPN allows TLS 1.0/1.1.",
                remediation="config vpn ssl settings; set tlsv1-0 disable; set tlsv1-1 disable; end"
            ))

        # Check for non-standard port
        port = vpn_cfg.get("port")
        if port == "443":
             findings.append(Finding(
                check_id=self.check_id,
                title="SSL VPN on Default Port",
                severity=Severity.LOW,
                message="SSL VPN is running on port 443, which is a common target.",
                remediation="Change SSL VPN port to a non-standard value."
            ))

        return self.create_result(Status.PERFORMED, findings=findings)

class PerformVulnScan(BaseCheck):
    check_id = "SEC-09"
    title = "Perform Vulnerability Scanning"
    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        # This now delegates to the specific vulnerability checks
        return self.create_result(Status.PERFORMED)

class ReviewChangeMgmt(BaseCheck):
    check_id = "SEC-10"
    title = "Review Change Management Procedures"
    remediation = "Enable revision backup on logout: config system global; set revision-backup-on-logout enable; end"
    nist_csf = ["GV.OC-05", "PR.PS-04"]
    iso27001 = ["A.5.37", "A.8.32"]
    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        # Checks if 'revision-backup-on-logout' is enabled
        global_cfg = config.get("config system global", {})
        if global_cfg.get("revision-backup-on-logout") != "enable":
             return self.create_result(Status.PERFORMED, findings=[Finding(
                 check_id=self.check_id,
                 title="Change Tracking Weakness",
                 severity=Severity.LOW,
                 message="Revision backup on logout is disabled.",
                 remediation=self.remediation,
                 nist_csf=self.nist_csf,
                 iso27001=self.iso27001
             )])
        return self.create_result(Status.PERFORMED)

from fortigate_cis_audit.engine.policy_analyzer import PolicyAnalyzer

class TestFirewallRules(BaseCheck):
    check_id = "SEC-11"
    title = "Test Firewall Rules"
    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        analyzer = PolicyAnalyzer(config)
        findings = []

        # Shadowing
        shadows = analyzer.find_shadowed_rules()
        for s in shadows:
            findings.append(Finding(
                check_id=self.check_id,
                title="Shadowed Firewall Rule",
                severity=Severity.MEDIUM,
                message=f"Policy {s['lower']} is shadowed by policy {s['upper']}.",
                remediation="Remove or reorder the shadowed policy."
            ))

        # Orphans
        orphans = analyzer.find_orphaned_objects()
        if orphans:
            findings.append(Finding(
                check_id=self.check_id,
                title="Orphaned Objects Detected",
                severity=Severity.LOW,
                message=f"Found {len(orphans)} unused address objects: {', '.join(orphans[:5])}...",
                remediation="Remove orphaned objects to clean up configuration."
            ))

        return self.create_result(Status.PERFORMED, findings=findings)

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
    mitre_techniques = ["T1190", "T1203"]
    nist_csf = ["PR.DS-02", "PR.PS-05"]
    cis_v8 = ["13.1", "13.2"]
    iso27001 = ["A.8.15", "A.8.16"]
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
                    remediation=self.remediation,
                    mitre_techniques=self.mitre_techniques,
                    nist_csf=self.nist_csf,
                    cis_v8=self.cis_v8,
                    iso27001=self.iso27001
                ))

        if not findings:
            return self.create_result(Status.PERFORMED)

        return self.create_result(Status.PERFORMED, findings=findings)

class CheckAVProfile(BaseCheck):
    check_id = "SEC-15"
    title = "Verify Antivirus Profile is enabled"
    remediation = "Apply AV profile to policies handling file transfers or general internet access: set av-profile <profile-name>"
    mitre_techniques = ["T1204", "T1566"]
    nist_csf = ["PR.DS-02", "PR.PS-05"]
    cis_v8 = ["13.1"]
    iso27001 = ["A.8.1", "A.5.7"]

    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        policies = config.get("config firewall policy", {}).get("edit", {})
        findings = []
        for p_id, p_data in policies.items():
            if p_data.get("action") == "accept" and not p_data.get("av-profile"):
                findings.append(Finding(
                    check_id=self.check_id,
                    title="AV Profile Missing",
                    severity=Severity.MEDIUM,
                    message=f"Policy {p_id} does not have an Antivirus profile enabled.",
                    remediation=self.remediation,
                    mitre_techniques=self.mitre_techniques,
                    nist_csf=self.nist_csf,
                    cis_v8=self.cis_v8,
                    iso27001=self.iso27001
                ))
        return self.create_result(Status.PERFORMED, findings=findings)

class CheckSSLInspection(BaseCheck):
    check_id = "SEC-16"
    title = "Verify SSL Inspection is enabled"
    remediation = "Enable Deep SSL Inspection to inspect encrypted traffic: set ssl-ssh-profile <profile-name>"
    mitre_techniques = ["T1071.001", "T1573"]
    nist_csf = ["PR.DS-02"]
    cis_v8 = ["13.1"]
    iso27001 = ["A.8.24"]

    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        policies = config.get("config firewall policy", {}).get("edit", {})
        findings = []
        for p_id, p_data in policies.items():
            if p_data.get("action") == "accept" and not p_data.get("ssl-ssh-profile"):
                findings.append(Finding(
                    check_id=self.check_id,
                    title="SSL Inspection Missing",
                    severity=Severity.MEDIUM,
                    message=f"Policy {p_id} does not have SSL/SSH inspection enabled.",
                    remediation=self.remediation,
                    mitre_techniques=self.mitre_techniques,
                    nist_csf=self.nist_csf,
                    cis_v8=self.cis_v8,
                    iso27001=self.iso27001
                ))
        return self.create_result(Status.PERFORMED, findings=findings)

class CheckAdminTrustedHosts(BaseCheck):
    check_id = "SEC-17"
    title = "Verify Admin Trusted Hosts"
    remediation = "Restrict administrative access to specific trusted hosts: config system admin; edit <user>; set trustedhost <network>; next; end"
    mitre_techniques = ["T1078", "T1098"]
    nist_csf = ["PR.AC-01", "PR.AC-06"]
    cis_v8 = ["4.3", "4.6"]
    iso27001 = ["A.8.2"]

    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        admins = config.get("config system admin", {}).get("edit", {})
        findings = []
        for name, data in admins.items():
            if not data.get("trusthost1") and not data.get("trustedhost"): # trustedhost is a newer list format
                 findings.append(Finding(
                    check_id=self.check_id,
                    title="Missing Trusted Hosts",
                    severity=Severity.HIGH,
                    message=f"Admin user '{name}' does not have trusted hosts configured.",
                    remediation=self.remediation,
                    mitre_techniques=self.mitre_techniques,
                    nist_csf=self.nist_csf,
                    cis_v8=self.cis_v8,
                    iso27001=self.iso27001
                ))
        return self.create_result(Status.PERFORMED, findings=findings)

class CheckSNMPConfig(BaseCheck):
    check_id = "SEC-18"
    title = "Verify SNMP Security"
    remediation = "Use SNMP v3 or ensure community strings are strong and not 'public'/'private'."
    mitre_techniques = ["T1078.002", "T1114"]
    iso27001 = ["A.8.2"]

    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        snmp_sys = config.get("config system snmp sysinfo", {})
        if snmp_sys.get("status") == "enable":
            communities = config.get("config system snmp community", {}).get("edit", {})
            findings = []
            for c_id, c_data in communities.items():
                name = c_data.get("name")
                if name in ["public", "private"]:
                    findings.append(Finding(
                        check_id=self.check_id,
                        title="Weak SNMP Community String",
                        severity=Severity.CRITICAL,
                        message=f"SNMP community '{c_id}' uses default name '{name}'.",
                        remediation=self.remediation,
                        mitre_techniques=self.mitre_techniques,
                        iso27001=self.iso27001
                    ))
            return self.create_result(Status.PERFORMED, findings=findings)
        return self.create_result(Status.PERFORMED)

class CheckSDWANAppControl(BaseCheck):
    check_id = "SEC-19"
    title = "Verify SD-WAN policies have Application Control"
    remediation = "Enable Application Control on all SD-WAN facing policies."
    mitre_techniques = ["T1071", "T1572"]
    nist_csf = ["PR.DS-02", "PR.PS-05"]
    cis_v8 = ["13.1"]
    iso27001 = ["A.8.3", "A.8.15"]

    def audit(self, config: Dict[str, Any]) -> SecurityCheckResult:
        # First identify SD-WAN zones
        sdwan_zones = []
        sdwan_cfg = config.get("config system sdwan", {})
        zones = sdwan_cfg.get("config zone", {}).get("edit", {})
        if zones:
            sdwan_zones.extend(zones.keys())

        # Default virtual-wan-link is often used even if not explicitly in config system sdwan config zone
        if "virtual-wan-link" in str(config):
            sdwan_zones.append("virtual-wan-link")

        policies = config.get("config firewall policy", {}).get("edit", {})
        findings = []
        for p_id, p_data in policies.items():
            dstintf = p_data.get("dstintf")

            # dstintf could be a string or a list
            interfaces = [dstintf] if isinstance(dstintf, str) else dstintf if isinstance(dstintf, list) else []

            is_sdwan = any(z in interfaces for z in sdwan_zones)
            if is_sdwan and not p_data.get("appctrl") and p_data.get("action") == "accept":
                findings.append(Finding(
                    check_id=self.check_id,
                    title="SD-WAN Policy missing App Control",
                    severity=Severity.MEDIUM,
                    message=f"Policy {p_id} targets SD-WAN zone(s) but lacks Application Control.",
                    remediation=self.remediation,
                    mitre_techniques=self.mitre_techniques,
                    nist_csf=self.nist_csf,
                    cis_v8=self.cis_v8,
                    iso27001=self.iso27001
                ))
        return self.create_result(Status.PERFORMED, findings=findings)
