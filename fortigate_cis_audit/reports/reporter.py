from rich.console import Console
from rich.table import Table
from fortigate_cis_audit.models import AuditReport, Status
import json
import csv
from jinja2 import Template

class Reporter:
    def __init__(self, report: AuditReport):
        self.report = report

    def to_console(self):
        console = Console()
        table = Table(title=f"FortiGate CIS Audit Report - Score: {self.report.get_score():.2f}%")
        table.add_column("ID", style="cyan")
        table.add_column("Title")
        table.add_column("Status", style="bold")
        table.add_column("Severity")

        for f in self.report.findings:
            color = "green" if f.status == Status.PASS else "red" if f.status == Status.FAIL else "yellow"
            table.add_row(f.check_id, f.title, f"[{color}]{f.status.value}[/{color}]", f.severity.value)

        console.print(table)

    def to_json(self) -> str:
        data = {
            "score": self.report.get_score(),
            "findings": [
                {
                    "id": f.check_id,
                    "title": f.title,
                    "status": f.status.value,
                    "severity": f.severity.value,
                    "message": f.message,
                    "remediation": f.remediation
                } for f in self.report.findings
            ]
        }
        return json.dumps(data, indent=2)

    def to_csv(self, filepath: str):
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["ID", "Title", "Status", "Severity", "Message", "Remediation"])
            for fnd in self.report.findings:
                writer.writerow([fnd.check_id, fnd.title, fnd.status.value, fnd.severity.value, fnd.message, fnd.remediation])

    def to_html(self, is_dashboard=False) -> str:
        template_str = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>FortiGate CIS Audit Dashboard</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f4f7f6; }
                .container { max-width: 1200px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                h1 { color: #333; text-align: center; }
                .summary-cards { display: flex; justify-content: space-around; margin-bottom: 30px; }
                .card { padding: 20px; border-radius: 8px; text-align: center; flex: 1; margin: 0 10px; color: white; }
                .score-card { background-color: #3498db; }
                .pass-card { background-color: #2ecc71; }
                .fail-card { background-color: #e74c3c; }
                .chart-container { width: 400px; margin: 20px auto; }
                table { border-collapse: collapse; width: 100%; margin-top: 20px; }
                th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
                th { background-color: #f2f2f2; }
                tr:hover { background-color: #f9f9f9; }
                .Pass { color: #2ecc71; font-weight: bold; }
                .Fail { color: #e74c3c; font-weight: bold; }
                .Warn { color: #f39c12; font-weight: bold; }
                pre { background: #f8f8f8; padding: 5px; border-radius: 4px; overflow-x: auto; max-width: 400px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>FortiGate CIS Audit Dashboard</h1>

                <div class="summary-cards">
                    <div class="card score-card">
                        <h3>Compliance Score</h3>
                        <div style="font-size: 2em;">{{ score }}%</div>
                    </div>
                    <div class="card pass-card">
                        <h3>Passed</h3>
                        <div style="font-size: 2em;">{{ pass_count }}</div>
                    </div>
                    <div class="card fail-card">
                        <h3>Failed</h3>
                        <div style="font-size: 2em;">{{ fail_count }}</div>
                    </div>
                </div>

                <div class="chart-container">
                    <canvas id="statusChart"></canvas>
                </div>

                <table>
                    <tr>
                        <th>ID</th>
                        <th>Title</th>
                        <th>Status</th>
                        <th>Severity</th>
                        <th>Remediation</th>
                    </tr>
                    {% for f in findings %}
                    <tr>
                        <td>{{ f.check_id }}</td>
                        <td>{{ f.title }}</td>
                        <td class="{{ f.status.value }}">{{ f.status.value }}</td>
                        <td>{{ f.severity.value }}</td>
                        <td><pre>{{ f.remediation }}</pre></td>
                    </tr>
                    {% endfor %}
                </table>
            </div>

            <script>
                const ctx = document.getElementById('statusChart').getContext('2d');
                new Chart(ctx, {
                    type: 'pie',
                    data: {
                        labels: ['Pass', 'Fail', 'Warn', 'Skip'],
                        datasets: [{
                            data: [{{ pass_count }}, {{ fail_count }}, {{ warn_count }}, {{ skip_count }}],
                            backgroundColor: ['#2ecc71', '#e74c3c', '#f39c12', '#95a5a6']
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            title: { display: true, text: 'Findings Distribution' }
                        }
                    }
                });
            </script>
        </body>
        </html>
        """
        pass_count = len([f for f in self.report.findings if f.status == Status.PASS])
        fail_count = len([f for f in self.report.findings if f.status == Status.FAIL])
        warn_count = len([f for f in self.report.findings if f.status == Status.WARN])
        skip_count = len([f for f in self.report.findings if f.status == Status.SKIP])

        template = Template(template_str)
        return template.render(
            score=f"{self.report.get_score():.2f}",
            findings=self.report.findings,
            pass_count=pass_count,
            fail_count=fail_count,
            warn_count=warn_count,
            skip_count=skip_count
        )
