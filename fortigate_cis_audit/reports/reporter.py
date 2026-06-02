from rich.console import Console
from rich.table import Table
from fortigate_cis_audit.models import AuditReport, Status, Severity
import json
import csv
from jinja2 import Template

class Reporter:
    def __init__(self, report: AuditReport):
        self.report = report

    def to_console(self):
        console = Console()
        summary = self.report.get_summary()
        console.print(f"\n[bold]Audit Executive Summary[/bold]")
        console.print(f"Risk Score: {self.report.get_risk_score():.2f}")
        console.print(f"Performed: {summary['performed']} | Failed: {summary['failed']} | Skipped: {summary['skipped']}\n")

        table = Table(title="Security Audit Results")
        table.add_column("Check Name", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("Findings", style="magenta")
        table.add_column("Duration (s)", justify="right")

        for r in self.report.check_results:
            status_color = "green" if r.status == Status.PERFORMED else "red" if r.status == Status.FAILED else "yellow"
            table.add_row(
                r.check_name,
                f"[{status_color}]{r.status.value.upper()}[/{status_color}]",
                str(len(r.findings)),
                f"{r.duration_seconds:.2f}"
            )

        console.print(table)

    def to_json(self) -> str:
        data = {
            "version": self.report.version,
            "risk_score": self.report.get_risk_score(),
            "summary": self.report.get_summary(),
            "results": [
                {
                    "check_name": r.check_name,
                    "status": r.status.value,
                    "timestamp": r.timestamp,
                    "duration_seconds": r.duration_seconds,
                    "findings": [
                        {
                            "id": f.check_id,
                            "title": f.title,
                            "severity": f.severity.value,
                            "message": f.message,
                            "remediation": f.remediation
                        } for f in r.findings
                    ],
                    "error_message": r.error_message,
                    "skip_reason": r.skip_reason
                } for r in self.report.check_results
            ]
        }
        return json.dumps(data, indent=2)

    def to_csv(self, filepath: str):
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Check Name", "Status", "Findings Count", "Duration", "Error/Skip Reason"])
            for r in self.report.check_results:
                reason = r.error_message or r.skip_reason or ""
                writer.writerow([r.check_name, r.status.value, len(r.findings), r.duration_seconds, reason])

    def to_html(self) -> str:
        template_str = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Audit Dashboard</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f4f7f6; }
                .container { max-width: 1200px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                h1 { color: #333; text-align: center; }
                .summary-cards { display: flex; justify-content: space-around; margin-bottom: 30px; }
                .card { padding: 20px; border-radius: 8px; text-align: center; flex: 1; margin: 0 10px; color: white; }
                .score-card { background-color: #3498db; }
                .performed-card { background-color: #2ecc71; }
                .failed-card { background-color: #e74c3c; }
                .skipped-card { background-color: #f39c12; }
                .chart-container { width: 400px; margin: 20px auto; }
                table { border-collapse: collapse; width: 100%; margin-top: 20px; }
                th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
                th { background-color: #f2f2f2; }
                tr:hover { background-color: #f9f9f9; }
                .performed { color: #2ecc71; font-weight: bold; }
                .failed { color: #e74c3c; font-weight: bold; }
                .skipped { color: #f39c12; font-weight: bold; }
                .remediation-matrix { margin-top: 40px; }
                .severity-critical { color: white; background: #c0392b; padding: 2px 5px; border-radius: 3px; }
                .severity-high { color: white; background: #e67e22; padding: 2px 5px; border-radius: 3px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Security Audit Dashboard - v{{ version }}</h1>

                <div class="summary-cards">
                    <div class="card score-card">
                        <h3>Risk Score</h3>
                        <div style="font-size: 2em;">{{ risk_score }}</div>
                    </div>
                    <div class="card performed-card">
                        <h3>Performed</h3>
                        <div style="font-size: 2em;">{{ summary.performed }}</div>
                    </div>
                    <div class="card failed-card">
                        <h3>Failed</h3>
                        <div style="font-size: 2em;">{{ summary.failed }}</div>
                    </div>
                    <div class="card skipped-card">
                        <h3>Skipped</h3>
                        <div style="font-size: 2em;">{{ summary.skipped }}</div>
                    </div>
                </div>

                <div class="chart-container">
                    <canvas id="statusChart"></canvas>
                </div>

                <h2>Check Results</h2>
                <table>
                    <tr>
                        <th>Check Name</th>
                        <th>Status</th>
                        <th>Duration (s)</th>
                        <th>Findings</th>
                        <th>Details</th>
                    </tr>
                    {% for r in results %}
                    <tr>
                        <td>{{ r.check_name }}</td>
                        <td class="{{ r.status }}">{{ r.status.upper() }}</td>
                        <td>{{ "%.2f"|format(r.duration_seconds) }}</td>
                        <td>{{ r.findings|length }}</td>
                        <td>{{ r.error_message or r.skip_reason or "" }}</td>
                    </tr>
                    {% endfor %}
                </table>

                <div class="remediation-matrix">
                    <h2>Remediation Matrix</h2>
                    <table>
                        <tr>
                            <th>Severity</th>
                            <th>Issue</th>
                            <th>Remediation</th>
                            <th>Effort</th>
                        </tr>
                        {% for r in results %}
                            {% for f in r.findings %}
                            <tr>
                                <td><span class="severity-{{ f.severity }}">{{ f.severity.upper() }}</span></td>
                                <td>{{ f.message }}</td>
                                <td>{{ f.remediation }}</td>
                                <td>{{ f.effort_estimate }}</td>
                            </tr>
                            {% endfor %}
                        {% endfor %}
                    </table>
                </div>
            </div>

            <script>
                const ctx = document.getElementById('statusChart').getContext('2d');
                new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: ['Performed', 'Failed', 'Skipped'],
                        datasets: [{
                            data: [{{ summary.performed }}, {{ summary.failed }}, {{ summary.skipped }}],
                            backgroundColor: ['#2ecc71', '#e74c3c', '#f39c12']
                        }]
                    }
                });
            </script>
        </body>
        </html>
        """
        template = Template(template_str)
        return template.render(
            version=self.report.version,
            risk_score=f"{self.report.get_risk_score():.2f}",
            summary=self.report.get_summary(),
            results=[
                {
                    "check_name": r.check_name,
                    "status": r.status.value,
                    "duration_seconds": r.duration_seconds,
                    "findings": r.findings,
                    "error_message": r.error_message,
                    "skip_reason": r.skip_reason
                } for r in self.report.check_results
            ]
        )
