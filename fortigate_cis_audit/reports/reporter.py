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

    def to_html(self) -> str:
        template_str = """
        <html>
        <head>
            <title>FortiGate CIS Audit Report</title>
            <style>
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                tr:nth-child(even) { background-color: #f2f2f2; }
                .Pass { color: green; }
                .Fail { color: red; }
                .Warn { color: orange; }
            </style>
        </head>
        <body>
            <h1>Audit Report</h1>
            <p>Overall Compliance Score: {{ score }}%</p>
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
        </body>
        </html>
        """
        template = Template(template_str)
        return template.render(
            score=f"{self.report.get_score():.2f}",
            findings=self.report.findings
        )
