import re
from typing import Dict, Any, List

class FortiOSParser:
    def __init__(self, config_text: str):
        self.config_text = config_text

    def parse(self) -> Dict[str, Any]:
        lines = self.config_text.splitlines()
        result, _ = self._parse_recursive(lines, 0)
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
                parts = line[4:].split(maxsplit=1)
                if len(parts) == 2:
                    name, value = parts
                    result[name] = value.strip('"')
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
