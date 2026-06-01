import click
import sys
import yaml
import os
from fortigate_cis_audit.connectors.base import FileConnector, SSHConnector, APIConnector
from fortigate_cis_audit.parsers.fortios_parser import parse_config
from fortigate_cis_audit.engine.audit_engine import AuditEngine
from fortigate_cis_audit.reports.reporter import Reporter
from fortigate_cis_audit.checks.section1_2 import CheckHTTPSOnly, CheckIdleTimeout, CheckSSHv2Only
from fortigate_cis_audit.checks.section3 import CheckSyslogConfigured
from fortigate_cis_audit.checks.section5 import CheckAnyAnyPolicy
from fortigate_cis_audit.checks.sections4_7 import CheckNTPConfigured, CheckIKEv2Only, CheckUSBAutoInstall
from fortigate_cis_audit.models import Status, Severity, CISLevel

def get_all_checks():
    # In a real app, this might use discovery
    return [
        CheckHTTPSOnly(),
        CheckIdleTimeout(),
        CheckSSHv2Only(),
        CheckSyslogConfigured(),
        CheckNTPConfigured(),
        CheckAnyAnyPolicy(),
        CheckIKEv2Only(),
        CheckUSBAutoInstall(),
    ]

@click.command()
@click.option('--host', help='FortiGate IP/Hostname')
@click.option('--user', help='Username')
@click.option('--password', help='Password')
@click.option('--key', help='Path to SSH private key')
@click.option('--file', help='Path to offline config file')
@click.option('--profile', help='Path to YAML profile for credentials/target')
@click.option('--output', type=click.Choice(['console', 'json', 'html', 'csv']), default='console')
@click.option('--report-dir', default='.', help='Directory to save reports')
@click.option('--level', type=click.Choice(['L1', 'L2', 'all']), default='all', help='Filter by CIS benchmark level')
@click.option('--section', help='Comma-separated section numbers to run (e.g., 1,3,5)')
@click.option('--severity', type=click.Choice(['Critical', 'High', 'Medium', 'Low', 'Info']), help='Filter findings by severity')
@click.option('--exclude', help='Comma-separated check IDs to skip')
@click.option('--fail-on-critical', is_flag=True, help='Exit with code 1 if any critical finding')
@click.option('--list-checks', is_flag=True, help='List all available checks and exit')
@click.option('--check-id', help='Run only a specific check ID')
def main(host, user, password, key, file, profile, output, report_dir, level, section, severity, exclude, fail_on_critical, list_checks, check_id):
    """FortiGate CIS Audit Tool"""

    all_available_checks = get_all_checks()

    if list_checks:
        click.echo("Available CIS Checks:")
        for c in all_available_checks:
            click.echo(f"- {c.check_id}: {c.title} ({c.level.value}, {c.severity.value})")
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

    parsed_config = parse_config(config_text)

    # Filter checks
    checks_to_run = all_available_checks

    if check_id:
        checks_to_run = [c for c in checks_to_run if c.check_id == check_id]

    if level != 'all':
        checks_to_run = [c for c in checks_to_run if c.level.value == level]

    if section:
        sections = [s.strip() for s in section.split(',')]
        checks_to_run = [c for c in checks_to_run if any(c.section.startswith(s) for s in sections)]

    if exclude:
        excludes = [e.strip() for e in exclude.split(',')]
        checks_to_run = [c for c in checks_to_run if c.check_id not in excludes]

    engine = AuditEngine(parsed_config, checks_to_run)
    report = engine.run()

    # Filter findings by severity if requested
    if severity:
        report.findings = [f for f in report.findings if f.severity.value == severity]

    reporter = Reporter(report)

    if output == 'console':
        reporter.to_console()
    elif output == 'json':
        click.echo(reporter.to_json())
    elif output == 'html':
        html_content = reporter.to_html()
        os.makedirs(report_dir, exist_ok=True)
        with open(f"{report_dir}/audit_report.html", "w") as f:
            f.write(html_content)
        click.echo(f"Report saved to {report_dir}/audit_report.html")
    elif output == 'csv':
        os.makedirs(report_dir, exist_ok=True)
        reporter.to_csv(f"{report_dir}/audit_report.csv")
        click.echo(f"Report saved to {report_dir}/audit_report.csv")

    if fail_on_critical:
        criticals = [f for f in report.findings if f.severity == Severity.CRITICAL and f.status == Status.FAIL]
        if criticals:
            click.echo(f"Found {len(criticals)} critical findings!", err=True)
            sys.exit(1)

if __name__ == '__main__':
    main()
