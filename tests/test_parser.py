from fortigate_cis_audit.parsers.fortios_parser import parse_config
import json

def test_basic_parse():
    config = """
config system global
    set hostname "FortiGate-VM64"
    set admin-sport 443
end
config system admin
    edit "admin"
        set password-policy "default"
        set vdom "root"
    next
end
"""
    parsed = parse_config(config)
    assert parsed["config system global"]["hostname"] == "FortiGate-VM64"
    assert parsed["config system global"]["admin-sport"] == "443"
    assert parsed["config system admin"]["edit"]["admin"]["vdom"] == "root"

if __name__ == "__main__":
    test_basic_parse()
    print("Test passed!")
