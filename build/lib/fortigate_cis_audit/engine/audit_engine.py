import time
from typing import List, Dict, Any, Optional
from fortigate_cis_audit.models import AuditReport, SecurityCheckResult, Status, Severity
from fortigate_cis_audit.engine.base_check import BaseCheck
from rich.console import Console

class AuditEngine:
    def __init__(self,
                 config: Dict[str, Any],
                 checks: List[BaseCheck],
                 fail_fast: bool = False,
                 include_checks: Optional[List[str]] = None,
                 skip_checks: Optional[List[str]] = None,
                 severity_threshold: Optional[str] = None):
        self.config = config
        self.checks = checks
        self.fail_fast = fail_fast
        self.include_checks = include_checks
        self.skip_checks = skip_checks
        self.severity_threshold = severity_threshold
        self.console = Console()

    def run(self) -> AuditReport:
        report = AuditReport()
        total_checks = len(self.checks)

        for i, check in enumerate(self.checks, 1):
            start_time = time.time()
            check_name = check.title

            # CLI Progress Display
            self.console.print(f"[{i}/{total_checks}] {check_name} ... ", end="")

            # Check for inclusion/exclusion
            if self.include_checks and check.check_id not in self.include_checks and check.title not in self.include_checks:
                 self._add_skipped(report, check, "not_included", start_time)
                 continue

            if self.skip_checks and (check.check_id in self.skip_checks or check.title in self.skip_checks):
                 self._add_skipped(report, check, "user_opt_out", start_time)
                 continue

            try:
                # In the new model, check.audit should return SecurityCheckResult
                # or we wrap the old finding in a result
                result = check.audit(self.config)
                result.duration_seconds = time.time() - start_time

                # Filter findings by severity threshold
                if self.severity_threshold:
                    threshold_val = self._severity_to_int(Severity(self.severity_threshold))
                    result.findings = [f for f in result.findings if self._severity_to_int(f.severity) >= threshold_val]

                report.check_results.append(result)

                status_char = "✅" if result.status == Status.PERFORMED else "❌" if result.status == Status.FAILED else "⏭️"
                self.console.print(f"{status_char} {result.status.value.upper()}")

                if self.fail_fast and result.status == Status.FAILED:
                    self.console.print("[bold red]Fail-fast enabled. Stopping audit.[/bold red]")
                    break

            except Exception as e:
                result = SecurityCheckResult(
                    check_name=check_name,
                    status=Status.FAILED,
                    error_message=str(e),
                    duration_seconds=time.time() - start_time
                )
                report.check_results.append(result)
                self.console.print(f"❌ FAILED (Error: {e})")
                if self.fail_fast:
                    break

        return report

    def _add_skipped(self, report, check, reason, start_time):
        result = SecurityCheckResult(
            check_name=check.title,
            status=Status.SKIPPED,
            skip_reason=reason,
            duration_seconds=time.time() - start_time
        )
        report.check_results.append(result)
        self.console.print(f"⏭️ SKIPPED ({reason})")

    def _severity_to_int(self, sev: Severity) -> int:
        mapping = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4
        }
        return mapping.get(sev, 0)
