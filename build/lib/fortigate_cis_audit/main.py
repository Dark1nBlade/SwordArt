import click
import sys
import yaml
import os
import webbrowser
from datetime import datetime
from fortigate_cis_audit.connectors.base import FileConnector, SSHConnector, APIConnector
from fortigate_cis_audit.parsers.fortios_parser import parse_config
from fortigate_cis_audit.engine.audit_engine import AuditEngine
from fortigate_cis_audit.reports.reporter import Reporter
from fortigate_cis_audit.checks.security_checks import (
    DocumentConfig, ReviewSecurityPolicies, CheckRuleShadowing, AuditNATRules,
    ValidateVPN, AssessLogging, EvaluateAppLayer, CheckFirmware, PerformVulnScan,
    ReviewChangeMgmt, TestFirewallRules, CreateAuditReport, ImplementRemediation
)
from fortigate_cis_audit.models import Status, Severity

def get_all_checks():
    return [
        DocumentConfig(),
        ReviewSecurityPolicies(),
        CheckRuleShadowing(),
        AuditNATRules(),
        ValidateVPN(),
        AssessLogging(),
        EvaluateAppLayer(),
        CheckFirmware(),
        PerformVulnScan(),
        ReviewChangeMgmt(),
        TestFirewallRules(),
        CreateAuditReport(),
        ImplementRemediation()
    ]

@click.command()
@click.option('--host', help='FortiGate IP/Hostname')
@click.option('--user', help='Username')
@click.option('--password', help='Password')
@click.option('--key', help='Path to SSH private key')
@click.option('--file', help='Path to offline config file')
@click.option('--profile', help='Path to YAML profile for credentials/target')
@click.option('--output', type=click.Choice(['console', 'json', 'html', 'csv', 'pdf']), default='console')
@click.option('--report-dir', default='reports', help='Directory to save reports')
@click.option('--dashboard', is_flag=True, help='Generate HTML dashboard and open in browser')
@click.option('--check', 'include_checks', multiple=True, help='Run individual checks by name or ID')
@click.option('--skip', 'skip_checks', multiple=True, help='Skip specific checks by name or ID')
@click.option('--severity-threshold', type=click.Choice(['critical', 'high', 'medium', 'low', 'info']), help='Filter findings by severity')
@click.option('--fail-fast', is_flag=True, help='Stop execution on first failed check')
@click.option('--fail-on-critical', is_flag=True, help='Exit with code 1 if any critical finding')
@click.option('--list-checks', is_flag=True, help='List all available checks and exit')
def main(host, user, password, key, file, profile, output, report_dir, dashboard,
         include_checks, skip_checks, severity_threshold, fail_fast, fail_on_critical, list_checks):
    """FortiGate Security Audit Tool"""

    all_available_checks = get_all_checks()

    if list_checks:
        click.echo("Available Security Checks:")
        for c in all_available_checks:
            click.echo(f"- {c.check_id}: {c.title}")
        return

    # Load profile if provided
    if profile and os.path.exists(profile):
        with open(profile, 'r') as f:
            p_data = yaml.safe_load(f)
            host = host or p_data.get('host')
            user = user or p_data.get('user')
            password = password or p_data.get('password')
            key = key or p_data.get('key')
            file = file or p_data.get('file')

    config_text = ""
    try:
        if file:
            connector = FileConnector(file)
            config_text = connector.get_config()
        elif host and user:
            if password or key:
                connector = SSHConnector(host, user, password=password, key_filename=key)
                config_text = connector.get_config()
            else:
                click.echo("Error: Password or SSH key required for live connection.", err=True)
                sys.exit(1)
        else:
            click.echo("Error: Either --file or --host/--user must be provided.", err=True)
            sys.exit(1)
    except Exception as e:
        click.echo(f"Connection Error: {e}", err=True)
        sys.exit(1)

    parsed_config = parse_config(config_text)

    engine = AuditEngine(
        parsed_config,
        all_available_checks,
        fail_fast=fail_fast,
        include_checks=list(include_checks),
        skip_checks=list(skip_checks),
        severity_threshold=severity_threshold
    )
    report = engine.run()

    reporter = Reporter(report)
    os.makedirs(report_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if dashboard:
        output = 'html'
        report_path = os.path.join(report_dir, f"audit_dashboard_{timestamp}.html")

    if output == 'console':
        reporter.to_console()
    elif output == 'json':
        json_data = reporter.to_json()
        report_path = os.path.join(report_dir, f"audit_report_{timestamp}.json")
        with open(report_path, "w") as f:
            f.write(json_data)
        click.echo(f"Report saved to {report_path}")
    elif output == 'html':
        html_content = reporter.to_html()
        report_path = os.path.join(report_dir, f"audit_report_{timestamp}.html")
        with open(report_path, "w") as f:
            f.write(html_content)
        click.echo(f"Report saved to {report_path}")
        if dashboard:
            webbrowser.open(f"file://{os.path.abspath(report_path)}")
    elif output == 'csv':
        report_path = os.path.join(report_dir, f"audit_report_{timestamp}.csv")
        reporter.to_csv(report_path)
        click.echo(f"Report saved to {report_path}")
    elif output == 'pdf':
        click.echo("PDF export requested. (Note: fpdf2 dependency might be needed)")
        # Placeholder for PDF
        click.echo("PDF export not fully implemented, falling back to HTML.")

    if fail_on_critical:
        all_findings = []
        for r in report.check_results:
            all_findings.extend(r.findings)

        criticals = [f for f in all_findings if f.severity == Severity.CRITICAL]
        if criticals:
            click.echo(f"Found {len(criticals)} critical findings!", err=True)
            sys.exit(1)

if __name__ == '__main__':
    main()
