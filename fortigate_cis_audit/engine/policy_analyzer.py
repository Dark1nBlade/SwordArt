from typing import Dict, Any, List
from fortigate_cis_audit.models import Finding, Severity

class PolicyAnalyzer:
    """
    Advanced firewall policy analyzer for shadowing and object consistency.
    """
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.policies = config.get("config firewall policy", {}).get("edit", {})
        self.addresses = config.get("config firewall address", {}).get("edit", {})
        self.addrgroups = config.get("config firewall addrgrp", {}).get("edit", {})
        self.services = config.get("config firewall service custom", {}).get("edit", {})

    def find_shadowed_rules(self) -> List[Dict[str, Any]]:
        findings = []
        policy_list = list(self.policies.items())

        for i, (p1_id, p1_data) in enumerate(policy_list):
            for j in range(i + 1, len(policy_list)):
                p2_id, p2_data = policy_list[j]

                # Simple shadowing heuristic: exact match on src/dst/service
                if (p1_data.get("srcaddr") == p2_data.get("srcaddr") and
                    p1_data.get("dstaddr") == p2_data.get("dstaddr") and
                    p1_data.get("service") == p2_data.get("service") and
                    p1_data.get("srcintf") == p2_data.get("srcintf") and
                    p1_data.get("dstintf") == p2_data.get("dstintf") and
                    p1_data.get("action") == p2_data.get("action")):

                    findings.append({
                        "upper": p1_id,
                        "lower": p2_id,
                        "reason": "Exact match shadowing"
                    })
        return findings

    def find_orphaned_objects(self) -> List[str]:
        referenced_addrs = set()
        for p in self.policies.values():
            src = p.get("srcaddr")
            dst = p.get("dstaddr")
            if isinstance(src, list): referenced_addrs.update(src)
            elif src: referenced_addrs.add(src)
            if isinstance(dst, list): referenced_addrs.update(dst)
            elif dst: referenced_addrs.add(dst)

        for g in self.addrgroups.values():
            m = g.get("member")
            if isinstance(m, list): referenced_addrs.update(m)
            elif m: referenced_addrs.add(m)

        orphans = []
        for name in self.addresses.keys():
            if name not in referenced_addrs and name != "all":
                orphans.append(name)
        return orphans
