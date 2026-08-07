"""YARA Scanning Engine - Real rule compilation and file/memory scanning."""
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False


@dataclass
class YaraMatch:
    rule_name: str
    namespace: str
    tags: List[str]
    strings_matched: List[Dict[str, Any]]
    meta: Dict[str, Any]


@dataclass
class YaraScanResult:
    target: str
    scan_type: str
    matches: List[YaraMatch] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    scan_duration_ms: float = 0.0


class YaraService:

    def __init__(self):
        self._compiled_rules: Optional[Any] = None
        self._rules_map: Dict[str, Any] = {}

    def compile_rules(self, rule_texts: Dict[str, str]) -> Dict[str, Any]:
        """Compile YARA rules from a dict of {rule_id: rule_text}."""
        self._rules_map = {}
        try:
            if HAS_YARA:
                compiled = {}
                for rid, text in rule_texts.items():
                    try:
                        rules = yara.compile(source=text)
                        compiled[rid] = rules
                        self._rules_map[rid] = rules
                    except Exception as e:
                        self._rules_map[rid] = None
                self._compiled_rules = compiled
            else:
                for rid, text in rule_texts.items():
                    self._rules_map[rid] = self._compile_regex(text)
            return self._rules_map
        except Exception as e:
            return {}

    def _compile_regex(self, rule_text: str) -> List[Dict[str, Any]]:
        """Fallback: extract strings from YARA rule and compile as regex."""
        patterns = []
        for line in rule_text.split('\n'):
            line = line.strip()
            match = re.match(r'\$(\w+)\s*=\s*["\'](.+?)["\']', line)
            if match:
                name, pattern = match.group(1), match.group(2)
                try:
                    patterns.append({"name": name, "regex": re.compile(re.escape(pattern), re.IGNORECASE)})
                except Exception:
                    pass
        return patterns

    def scan_file(self, filepath: str) -> YaraScanResult:
        """Scan a single file with all compiled rules."""
        import time
        start = time.time()
        result = YaraScanResult(target=filepath, scan_type="file")

        if not os.path.exists(filepath):
            result.errors.append(f"File not found: {filepath}")
            result.scan_duration_ms = (time.time() - start) * 1000
            return result

        try:
            if HAS_YARA and self._compiled_rules:
                for rid, rules in self._compiled_rules.items():
                    try:
                        matches = rules.match(filepath)
                        for m in matches:
                            result.matches.append(YaraMatch(
                                rule_name=m.rule,
                                namespace=m.namespace,
                                tags=list(m.tags or []),
                                strings_matched=[{"identifier": s.identifier, "offset": s.instances[0].offset if s.instances else 0} for s in m.strings],
                                meta=dict(m.meta or {}),
                            ))
                    except Exception as e:
                        result.errors.append(f"Rule {rid}: {e}")
            else:
                with open(filepath, 'r', errors='ignore') as f:
                    content = f.read()
                result = self._regex_scan(content, filepath, result)
        except Exception as e:
            result.errors.append(str(e))

        result.scan_duration_ms = (time.time() - start) * 1000
        return result

    def scan_memory(self, pid: int) -> YaraScanResult:
        """Scan process memory (Linux: /proc/pid/mem, others: subprocess)."""
        import time
        start = time.time()
        result = YaraScanResult(target=f"pid:{pid}", scan_type="memory")

        try:
            if os.path.exists(f"/proc/{pid}/mem"):
                with open(f"/proc/{pid}/mem", 'rb') as f:
                    content = f.read(1024 * 1024 * 10)
                result = self._regex_scan(content.decode('utf-8', errors='ignore'), f"pid:{pid}", result)
            elif os.name == 'nt':
                import tempfile
                proc_dump = subprocess.run(['powershell', '-c', f'Get-Process -Id {pid} | Select-Object -ExpandProperty Path'], capture_output=True, text=True, timeout=10)
                if proc_dump.stdout.strip():
                    result = self.scan_file(proc_dump.stdout.strip())
        except Exception as e:
            result.errors.append(str(e))

        result.scan_duration_ms = (time.time() - start) * 1000
        return result

    def scan_directory(self, directory: str) -> YaraScanResult:
        """Recursively scan a directory."""
        import time
        start = time.time()
        result = YaraScanResult(target=directory, scan_type="directory")

        try:
            for root, _, files in os.walk(directory):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        size = os.path.getsize(fpath)
                        if size > 100 * 1024 * 1024:
                            continue
                        sub_result = self.scan_file(fpath)
                        result.matches.extend(sub_result.matches)
                        result.errors.extend(sub_result.errors)
                    except (OSError, PermissionError):
                        pass
        except Exception as e:
            result.errors.append(str(e))

        result.scan_duration_ms = (time.time() - start) * 1000
        return result

    def _regex_scan(self, content: str, target: str, result: YaraScanResult) -> YaraScanResult:
        """Fallback regex-based scanning."""
        for rid, patterns in self._rules_map.items():
            if not patterns:
                continue
            if isinstance(patterns, list):
                matched = []
                for p in patterns:
                    if isinstance(p, dict) and 'regex' in p:
                        if p['regex'].search(content):
                            matched.append({"identifier": p['name'], "offset": 0})
                if matched:
                    result.matches.append(YaraMatch(
                        rule_name=rid, namespace="default", tags=[],
                        strings_matched=matched, meta={},
                    ))
        return result

    def scan_with_rules(self, target: str, rule_ids: List[str]) -> YaraScanResult:
        """Scan target with specific rules only."""
        import time
        start = time.time()

        if os.path.exists(target):
            result = self.scan_file(target)
        else:
            result = YaraScanResult(target=target, scan_type="target", errors=[f"Target not found: {target}"])

        result.matches = [m for m in result.matches if m.rule_name in rule_ids]
        result.scan_duration_ms = (time.time() - start) * 1000
        return result
