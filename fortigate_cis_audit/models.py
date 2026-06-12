from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime

class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

class Status(Enum):
    # CIS Statuses
    PASS = "Pass"
    FAIL = "Fail"
    WARN = "Warn"
    SKIP = "Skip"
    # Security Statuses
    PERFORMED = "Performed"
    FAILED = "Failed"
    SKIPPED = "Skipped"

class CISLevel(Enum):
    L1 = "L1"
    L2 = "L2"

@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    status: Optional[Status] = None # For CIS compatibility
    message: str = ""
    remediation: str = ""
    evidence: str = ""
    effort_estimate: str = "Low"
    level: Optional[CISLevel] = None # For CIS compatibility
    section: str = "" # For CIS compatibility
    mitre_techniques: List[str] = field(default_factory=list)
    nist_csf: List[str] = field(default_factory=list)
    cis_v8: List[str] = field(default_factory=list)
    iso27001: List[str] = field(default_factory=list)

@dataclass
class SecurityCheckResult:
    check_name: str
    status: Status
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    duration_seconds: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    error_message: Optional[str] = None
    skip_reason: Optional[str] = None
    severity: Severity = Severity.INFO

@dataclass
class AuditReport:
    check_results: List[SecurityCheckResult] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list) # For CIS compatibility
    metadata: Dict[str, Any] = field(default_factory=dict)
    version: str = "0.2.0"

    def get_score(self) -> float:
        """
        Calculate a unified compliance score across all checks.
        A check is considered 'passed' if:
        1. It has status PASS.
        2. It has status PERFORMED and either no findings or only findings with status PASS.
        """
        relevant_results = [r for r in self.check_results if r.status not in [Status.SKIP, Status.SKIPPED]]
        if not relevant_results:
            return 0.0

        passed_count = 0
        for r in relevant_results:
            if r.status == Status.PASS:
                passed_count += 1
            elif r.status == Status.PERFORMED:
                # If it's a legacy CIS check wrapped in a result, check the finding status
                if r.findings:
                    if all(f.status == Status.PASS or f.status is None for f in r.findings):
                        # For non-CIS checks, status is None. We consider PERFORMED with findings as 'failed'
                        # in terms of compliance if those findings represent issues.
                        # However, some PERFORMED checks might just be 'Info'.
                        if all(f.severity == Severity.INFO for f in r.findings):
                            passed_count += 1
                        elif any(f.severity.value in ["Critical", "High", "Medium", "Low"] for f in r.findings):
                            # It has actual security findings, so it's not 'compliant'
                            pass
                        else:
                            passed_count += 1
                else:
                    # Performed with no findings is a pass
                    passed_count += 1

        return (passed_count / len(relevant_results)) * 100

    def get_risk_score(self) -> float:
        """
        Calculates a risk score from 0-100.
        0: No findings (Secure)
        100: Critical findings present (High Risk)
        """
        performed = [r for r in self.check_results if r.status in [Status.PERFORMED, Status.PASS]]
        if not performed: return 0.0

        total_weight = 0
        for r in performed:
            for f in r.findings:
                if f.severity == Severity.CRITICAL: total_weight += 20
                elif f.severity == Severity.HIGH: total_weight += 10
                elif f.severity == Severity.MEDIUM: total_weight += 5
                elif f.severity == Severity.LOW: total_weight += 1

        # Cap at 100
        return min(100.0, float(total_weight))

    def get_summary(self) -> Dict[str, int]:
        return {
            "performed": len([r for r in self.check_results if r.status in [Status.PERFORMED, Status.PASS]]),
            "failed": len([r for r in self.check_results if r.status in [Status.FAILED, Status.FAIL]]),
            "skipped": len([r for r in self.check_results if r.status in [Status.SKIPPED, Status.SKIP]])
        }

    def get_framework_summary(self) -> Dict[str, Any]:
        mitre = set()
        nist = set()
        cis = set()
        iso = set()

        all_findings = []
        for r in self.check_results:
            all_findings.extend(r.findings)

        for f in all_findings:
            mitre.update(f.mitre_techniques)
            nist.update(f.nist_csf)
            cis.update(f.cis_v8)
            iso.update(f.iso27001)

        return {
            "mitre": {"techniques": sorted(list(mitre)), "count": len(mitre)},
            "nist": {"subcategories": sorted(list(nist)), "count": len(nist)},
            "cis": {"safeguards": sorted(list(cis)), "count": len(cis)},
            "iso": {"controls": sorted(list(iso)), "count": len(iso)}
        }
