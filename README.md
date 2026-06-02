# FortiGate CIS Audit Tool

A Python-based CLI tool to audit FortiGate firewall configurations against the CIS Fortinet FortiOS Benchmark.

## Features

- **Multiple Input Methods**: Support for live devices (SSH/API) and offline config files.
- **Comprehensive CIS Checks**: Covers Management Access, Authentication, Logging, Network Services, Firewall Policies, VPN, and System Hardening.
- **Flexible Reporting**: Output results in Console, JSON, HTML, or CSV formats.
- **Interactive Dashboard**: Generate a visual HTML dashboard with Chart.js.
- **CI/CD Ready**: Exit codes for critical findings.

## Installation

```bash
pip install .
```

## Usage

### Audit an offline configuration file
```bash
fortigate-cis-audit --file backup.conf --output console
```

### Generate a visual dashboard
```bash
fortigate-cis-audit --file backup.conf --dashboard
```

### Audit a live device via SSH
```bash
fortigate-cis-audit --host 192.168.1.1 --user admin --password mypassword --output html
```

### CI/CD Integration
```bash
fortigate-cis-audit --file backup.conf --fail-on-critical
```

## CIS Benchmark Checks Implemented

- **CIS-1.1**: Ensure HTTPS-only admin access
- **CIS-1.4**: Check idle session timeout <= 5 minutes
- **CIS-2.3**: Ensure SSH v2 only
- **CIS-3.1**: Confirm syslog server is configured
- **CIS-4.3**: Ensure NTP is configured
- **CIS-5.1**: Flag any permit any any policies
- **CIS-6.1**: Enforce IKEv2 for IPsec tunnels
- **CIS-7.2**: Verify auto-install from USB is disabled

## Development

- `fortigate_cis_audit/`: Main package
- `tests/`: Unit tests
