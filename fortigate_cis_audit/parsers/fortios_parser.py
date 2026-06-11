import re
from typing import Dict, Any, List

class FortiOSParser:
    def __init__(self, config_text: str):
        self.config_text = config_text

    def parse(self) -> Dict[str, Any]:
        lines = self.config_text.splitlines()
        result, _ = self._parse_recursive(lines, 0)

        # Try to extract version from header if not in config
        version_match = re.search(r'#config-version=FortiGate-VM64-([^:]+)', self.config_text)
        if version_match:
            result["version_info"] = version_match.group(1)
        else:
            v_alt = re.search(r'set version ([^\n]+)', self.config_text)
            if v_alt:
                result["version_info"] = v_alt.group(1).strip()

        return result

    def _parse_recursive(self, lines: List[str], index: int) -> tuple[Dict[str, Any], int]:
        result = {}
        i = index
        while i < len(lines):
            line = lines[i].strip()

            if not line or line.startswith('#'):
                i += 1
                continue

            if line == 'end' or line == 'next':
                return result, i + 1

            if line.startswith('config '):
                key = line[7:].strip()
                sub_config, next_i = self._parse_recursive(lines, i + 1)
                result[f"config {key}"] = sub_config
                i = next_i
            elif line.startswith('edit '):
                key = line[5:].strip().strip('"')
                sub_config, next_i = self._parse_recursive(lines, i + 1)
                if "edit" not in result:
                    result["edit"] = {}
                result["edit"][key] = sub_config
                i = next_i
            elif line.startswith('set '):
                # Remove 'set ' prefix
                content = line[4:].strip()
                # Find the key (first word)
                parts = content.split(maxsplit=1)
                if len(parts) == 2:
                    name, rest = parts
                    # Extract all quoted values: "value1" "value2"
                    values = re.findall(r'"([^"]*)"', rest)
                    if not values:
                        # If no quoted values found, try unquoted single value
                        result[name] = rest.strip()
                    elif len(values) == 1:
                        result[name] = values[0]
                    else:
                        # Multiple values (like multiple interfaces or SD-WAN zones)
                        result[name] = values
                elif len(parts) == 1:
                    result[parts[0]] = True
                i += 1
            elif line.startswith('unset '):
                name = line[6:].strip()
                result[name] = None
                i += 1
            else:
                i += 1

        return result, i

def parse_config(config_text: str) -> Dict[str, Any]:
    parser = FortiOSParser(config_text)
    return parser.parse()
