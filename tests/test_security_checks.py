import pytest
from fortigate_cis_audit.parsers.fortios_parser import parse_config
from fortigate_cis_audit.checks.security_checks import ReviewSecurityPolicies
from fortigate_cis_audit.models import Status

def test_review_policies():
    config = """
    config firewall policy
        edit 1
            set srcaddr "all"
            set dstaddr "all"
            set action accept
        next
    end
    """
    parsed = parse_config(config)
    check = ReviewSecurityPolicies()
    result = check.audit(parsed)
    assert result.status == Status.PERFORMED
    assert len(result.findings) == 1
    assert "Policy 1 review" in result.findings[0].title
