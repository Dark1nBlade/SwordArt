import yaml
from fortigate_cis_audit.engine.base_check import BaseCheck
from fortigate_cis_audit.models import Status, Severity, CISLevel
from typing import Dict, Any, List

class YAMLCheck(BaseCheck):
    def __init__(self, check_def: Dict[str, Any]):
        self.check_id = check_def['check_id']
        self.title = check_def['title']
        self.level = CISLevel(check_def['level'])
        self.severity = Severity(check_def['severity'])
        self.section = check_def['section']
        self.remediation = check_def['remediation']
        self.path = check_def['path'] # e.g. "config system global.admintimeout"
        self.expected = check_def['expected']
        self.operator = check_def.get('operator', 'eq')

    def audit(self, config: Dict[str, Any]) -> Any:
        parts = self.path.split('.')
        current = config
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return self.create_finding(Status.FAIL, f"Path {self.path} not found in config")

        actual = current
        passed = False
        if self.operator == 'eq':
            passed = str(actual) == str(self.expected)
        elif self.operator == 'lte':
            passed = int(actual) <= int(self.expected)
        elif self.operator == 'contains':
            passed = str(self.expected) in str(actual)

        if passed:
            return self.create_finding(Status.PASS, f"Found expected value: {actual}")
        else:
            return self.create_finding(Status.FAIL, f"Found {actual}, expected {self.operator} {self.expected}")

def load_yaml_checks(filepath: str) -> List[YAMLCheck]:
    if not filepath or not os.path.exists(filepath):
        return []
    with open(filepath, 'r') as f:
        defs = yaml.safe_load(f)
    if not isinstance(defs, list):
        return []
    return [YAMLCheck(d) for d in defs]

import os
