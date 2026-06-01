import pytest
from fortigate_cis_audit.parsers.fortios_parser import parse_config
from fortigate_cis_audit.checks.section1_2 import CheckHTTPSOnly, CheckIdleTimeout
from fortigate_cis_audit.models import Status

def test_https_only_pass():
    config = """
    config system global
        set admin-https-redirect enable
    end
    """
    parsed = parse_config(config)
    check = CheckHTTPSOnly()
    finding = check.audit(parsed)
    assert finding.status == Status.PASS

def test_https_only_fail():
    config = """
    config system global
        set admin-https-redirect disable
    end
    """
    parsed = parse_config(config)
    check = CheckHTTPSOnly()
    finding = check.audit(parsed)
    assert finding.status == Status.FAIL

def test_idle_timeout_pass():
    config = "config system global\n set admintimeout 5\n end"
    parsed = parse_config(config)
    check = CheckIdleTimeout()
    finding = check.audit(parsed)
    assert finding.status == Status.PASS

def test_idle_timeout_fail():
    config = "config system global\n set admintimeout 10\n end"
    parsed = parse_config(config)
    check = CheckIdleTimeout()
    finding = check.audit(parsed)
    assert finding.status == Status.FAIL
