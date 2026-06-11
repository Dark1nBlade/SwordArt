from typing import List, Dict, Any
from fortigate_cis_audit.models import AuditReport, SecurityCheckResult, Status, Severity
import click

class RemediationEngine:
    """
    Handles automated remediation of security findings with risk levels.
    """
    def __init__(self, report: AuditReport, dry_run: bool = True):
        self.report = report
        self.dry_run = dry_run
        self.actions_log = []

    def remediate_all(self):
        click.echo(f"\n[Remediation] Starting auto-remediation (Dry Run: {self.dry_run})")

        # 1. Backup before change
        if not self.dry_run:
            click.echo("  [Safety] Creating configuration backup...")
            # Mock: execute backup config

        for result in self.report.check_results:
            for finding in result.findings:
                if not finding.remediation:
                    continue

                risk_level = self._get_risk_level(finding)

                if risk_level == "low":
                    self._apply_fix(finding, "Auto-applied")
                elif risk_level == "medium":
                    if self.dry_run:
                        self._apply_fix(finding, "Requires Approval (Dry Run)")
                    else:
                        if click.confirm(f"  [Approval] Apply fix for '{finding.title}'?", default=True):
                            self._apply_fix(finding, "Approved & Applied")
                else:
                    click.echo(f"  [Manual] '{finding.title}' is high-risk. Please review remediation manually.")

    def _get_risk_level(self, finding) -> str:
        if finding.severity in [Severity.LOW, Severity.INFO]:
            return "low"
        if finding.severity == Severity.MEDIUM:
            return "medium"
        return "high"

    def _apply_fix(self, finding, prefix: str):
        action = f"{prefix}: {finding.title} -> {finding.remediation}"
        if self.dry_run:
            click.echo(f"  [DRY RUN] {prefix}: {finding.remediation}")
        else:
            click.echo(f"  [EXECUTE] {prefix}: {finding.remediation}")
            # Real implementation would call SSHConnector.run_command(finding.remediation)
        self.actions_log.append(action)

    def get_remediation_summary(self):
        return self.actions_log
