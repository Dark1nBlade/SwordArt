from fortigate_cis_audit.engine.base_check import BaseCheck
from fortigate_cis_audit.models import Status, Severity, CISLevel
from typing import Dict, Any

class CheckNTPConfigured(BaseCheck):
    check_id = "CIS-4.3"
    title = "Ensure NTP is configured"
    level = CISLevel.L1
    severity = Severity.MEDIUM
    section = "4. Network & Services"
    remediation = "config system ntp\n  set status enable\n  set ntpsync enable\n  config ntpserver\n    edit 1\n      set server ntp.fortinet.net\n    next\n  end\nend"

    def audit(self, config: Dict[str, Any]) -> Any:
        ntp_cfg = config.get("config system ntp", {})
        status = ntp_cfg.get("status")
        if status == "enable":
            return self.create_finding(Status.PASS, "NTP is enabled.")
        else:
            return self.create_finding(Status.FAIL, "NTP is not enabled.")

class CheckIKEv2Only(BaseCheck):
    check_id = "CIS-6.1"
    title = "Enforce IKEv2 for IPsec tunnels"
    level = CISLevel.L1
    severity = Severity.MEDIUM
    section = "6. VPN"
    remediation = "config vpn ipsec phase1-interface\n  edit <name>\n    set ike-version 2\n  next\nend"

    def audit(self, config: Dict[str, Any]) -> Any:
        phase1_cfg = config.get("config vpn ipsec phase1-interface", {}).get("edit", {})
        if not phase1_cfg:
            return self.create_finding(Status.SKIP, "No IPsec tunnels configured.")

        v1_tunnels = []
        for name, data in phase1_cfg.items():
            if data.get("ike-version") != "2":
                v1_tunnels.append(name)

        if v1_tunnels:
            return self.create_finding(Status.FAIL, f"Tunnels using IKEv1: {', '.join(v1_tunnels)}")
        else:
            return self.create_finding(Status.PASS, "All IPsec tunnels use IKEv2.")

class CheckUSBAutoInstall(BaseCheck):
    check_id = "CIS-7.2"
    title = "Verify auto-install from USB is disabled"
    level = CISLevel.L1
    severity = Severity.LOW
    section = "7. System Hardening"
    remediation = "config system auto-install\n  set auto-install-config disable\n  set auto-install-image disable\nend"

    def audit(self, config: Dict[str, Any]) -> Any:
        usb_cfg = config.get("config system auto-install", {})
        cfg_install = usb_cfg.get("auto-install-config")
        img_install = usb_cfg.get("auto-install-image")

        if cfg_install == "disable" and img_install == "disable":
            return self.create_finding(Status.PASS, "USB auto-install is disabled.")
        else:
            return self.create_finding(Status.FAIL, "USB auto-install is enabled.")
