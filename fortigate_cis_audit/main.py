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
from fortigate_cis_audit.checks.section1_2 import CheckHTTPSOnly, CheckIdleTimeout, CheckSSHv2Only
from fortigate_cis_audit.checks.section3 import CheckSyslogConfigured
from fortigate_cis_audit.checks.section5 import CheckAnyAnyPolicy
from fortigate_cis_audit.checks.sections4_7 import CheckNTPConfigured, CheckIKEv2Only, CheckUSBAutoInstall
from fortigate_cis_audit.checks.security_checks import (
    DocumentConfig, ReviewSecurityPolicies, CheckRuleShadowing, AuditNATRules,
    ValidateVPN, AssessLogging, EvaluateAppLayer, CheckFirmware, PerformVulnScan,
    ReviewChangeMgmt, TestFirewallRules, CreateAuditReport, ImplementRemediation,
    CheckIPSConfigured
)
from fortigate_cis_audit.models import Status, Severity, CISLevel

def get_all_checks():
    return [
        # CIS Checks
        CheckHTTPSOnly(),
        CheckIdleTimeout(),
        CheckSSHv2Only(),
        CheckSyslogConfigured(),
        CheckNTPConfigured(),
        CheckAnyAnyPolicy(),
        CheckIKEv2Only(),
        CheckUSBAutoInstall(),
        # Security Checks
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
        ImplementRemediation(),
        CheckIPSConfigured()
    ]

@click.command()
@click.option('--host', help='FortiGate IP/Hostname')
@click.option('--user', help='Username')
@click.option('--password', help='Password')
@click.option('--key', help='Path to SSH private key')
@click.option('--file', help='Path to offline config file')
@click.option('--profile', help='Path to YAML profile for credentials/target')
@click.option('--output', type=click.Choice(['console', 'json', 'html', 'csv']), default='console')
@click.option('--report-dir', default='reports', help='Directory to save reports')
@click.option('--dashboard', is_flag=True, help='Generate HTML dashboard and open in browser')
@click.option('--check', 'include_checks', multiple=True, help='Run individual checks by name or ID')
@click.option('--skip', 'skip_checks', multiple=True, help='Skip specific checks by name or ID')
@click.option('--level', type=click.Choice(['L1', 'L2', 'all']), default='all', help='Filter by CIS benchmark level')
@click.option('--section', help='Comma-separated section numbers to run (e.g., 1,3,5)')
@click.option('--severity-threshold', type=click.Choice(['critical', 'high', 'medium', 'low', 'info']), help='Filter findings by severity')
@click.option('--fail-fast', is_flag=True, help='Stop execution on first failed check')
@click.option('--fail-on-critical', is_flag=True, help='Exit with code 1 if any critical finding')
@click.option('--list-checks', is_flag=True, help='List all available checks and exit')
@click.option('--list-zones', is_flag=True, help='List all configured zones and exit')
@click.option('--list-interfaces', is_flag=True, help='List all configured interfaces and exit')
@click.option('--wan', multiple=True, help='List of WAN interfaces (example: --wan port1 --wan port2)')
def main(host, user, password, key, file, profile, output, report_dir, dashboard,
         include_checks, skip_checks, level, section, severity_threshold, fail_fast, fail_on_critical, list_checks,
         list_zones, list_interfaces, wan):
    """FortiGate CIS & Security Audit Tool"""

    all_available_checks = get_all_checks()

    if list_checks:
        click.echo("Available Checks:")
        for c in all_available_checks:
            desc = f" ({c.level.value})" if hasattr(c, 'level') else ""
            click.echo(f"- {c.check_id}: {c.title}{desc}")
        return

    # Connection and config retrieval
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

    if list_zones:
        zones = parsed_config.get("config system zone", {}).get("edit", {})
        if not zones:
            click.echo("No zones configured.")
        else:
            click.echo("Configured Zones:")
            for zone_name, zone_data in zones.items():
                interface = zone_data.get("interface", "None")
                click.echo(f"- {zone_name} (Interfaces: {interface})")
        return

    if list_interfaces:
        interfaces = parsed_config.get("config system interface", {}).get("edit", {})
        if not interfaces:
            click.echo("No interfaces configured.")
        else:
            click.echo("Configured Interfaces:")
            for intf_name, intf_data in interfaces.items():
                ip = intf_data.get("ip", "N/A")
                allowaccess = intf_data.get("allowaccess", "None")
                click.echo(f"- {intf_name}: {ip} (Allow: {allowaccess})")
        return

    # Filter checks
    checks_to_run = all_available_checks

    if level != 'all':
        checks_to_run = [c for c in checks_to_run if hasattr(c, 'level') and c.level.value == level]

    if section:
        sections = [s.strip() for s in section.split(',')]
        checks_to_run = [c for c in checks_to_run if hasattr(c, 'section') and any(c.section.startswith(s) for s in sections)]

    engine = AuditEngine(
        parsed_config,
        checks_to_run,
        fail_fast=fail_fast,
        include_checks=list(include_checks),
        skip_checks=list(skip_checks),
        severity_threshold=severity_threshold,
        wan_interfaces=list(wan)
    )
    report = engine.run()

    reporter = Reporter(report)
    os.makedirs(report_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if dashboard:
        output = 'html'
        report_path = os.path.join(report_dir, f"audit_dashboard_{timestamp}.html")
    else:
        report_path = None

    if output == 'console':
        reporter.to_console()
    elif output == 'json':
        json_data = reporter.to_json()
        click.echo(json_data)
    elif output == 'html':
        html_content = reporter.to_html()
        if not report_path:
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

    if fail_on_critical:
        # Check for findings with CRITICAL severity and non-PASS/PERFORMED status
        failed_criticals = []
        for r in report.check_results:
            if r.status in [Status.FAILED, Status.FAIL]:
                for f in r.findings:
                    if f.severity == Severity.CRITICAL:
                        failed_criticals.append(f)

        if failed_criticals:
            click.echo(f"Found {len(failed_criticals)} critical findings!", err=True)
            sys.exit(1)

if __name__ == '__main__':
    main()
