from typing import Dict, Any, Optional

class FortiGuardConnector:
    """
    Mock FortiGuard connector for firmware and PSIRT intelligence.
    In a real implementation, this would query Fortinet APIs.
    """
    def __init__(self):
        # Mock data for demonstration
        self.latest_versions = {
            "FortiGate-VM64": "7.4.3",
            "FG-100F": "7.2.7",
            "FG-60F": "7.0.14"
        }
        self.eol_versions = ["6.0", "6.2", "5.6"]
        self.psirts = {
            "7.2.0": [{"id": "FG-IR-22-398", "severity": "Critical", "cve": "CVE-2022-42475"}],
            "7.0.0": [{"id": "FG-IR-22-398", "severity": "Critical", "cve": "CVE-2022-42475"}]
        }

    def get_latest_stable(self, model: str) -> Optional[str]:
        return self.latest_versions.get(model, "7.4.3")

    def is_eol(self, version: str) -> bool:
        major_minor = ".".join(version.split(".")[:2])
        return major_minor in self.eol_versions

    def get_vulnerabilities(self, version: str) -> list:
        return self.psirts.get(version, [])

def get_fortiguard_client():
    return FortiGuardConnector()
