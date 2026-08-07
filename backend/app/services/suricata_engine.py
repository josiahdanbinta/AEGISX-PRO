"""
AEGISX - Suricata Rule Parser & Evaluation Engine
Parses Suricata IDS rules and converts them into OpenSearch queries
for evaluation against ingested events.
"""
import re
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

ACTION_MAP = {"alert": 1, "pass": 0, "drop": 3, "reject": 3, "rejectsrc": 3, "rejectdst": 3, "rejectboth": 3}

CLASS_TYPE_SEVERITY = {
    "not-suspicious": "info", "unknown": "low", "bad-unknown": "medium",
    "attempted-recon": "medium", "successful-recon-limited": "medium",
    "successful-recon-largescale": "high", "attempted-dos": "medium",
    "successful-dos": "high", "attempted-user": "medium",
    "unsuccessful-user": "low", "successful-user": "high",
    "attempted-admin": "medium", "successful-admin": "critical",
    "rpc-portmap-decode": "medium", "shellcode-detect": "high",
    "string-detect": "medium", "suspicious-filename-detect": "medium",
    "suspicious-login": "medium", "system-call-detect": "low",
    "tcp-connection": "low", "trojan-activity": "critical",
    "unusual-client-port-connection": "medium",
    "network-scan": "low", "denial-of-service": "high",
    "non-standard-protocol": "low", "protocol-command-decode": "medium",
    "web-application-activity": "low", "web-application-attack": "high",
    "misc-activity": "low", "misc-attack": "high",
    "icmp-event": "low", "inappropriate-content": "medium",
    "policy-violation": "medium", "default-login-attempt": "medium",
    "targeted-activity": "high", "exploit-kit": "critical",
    "social-engineering": "medium", "credential-theft": "critical",
    "data-loss": "critical", "not-suspicious": "info",
}

REFERENCE_PATTERN = re.compile(r'reference\s*:\s*(\w+)\s*,\s*(.+?);', re.IGNORECASE)
CONTENT_PATTERN = re.compile(r'content\s*:\s*"((?:\\.|[^"\\])*)"\s*;', re.IGNORECASE)
PCRE_PATTERN = re.compile(r'pcre\s*:\s*"((?:\\.|[^"\\])*)"\s*;', re.IGNORECASE)
META_PATTERN = re.compile(r'(\w+)\s*:\s*(.+?)\s*;', re.IGNORECASE)
FLOW_PATTERN = re.compile(r'flow\s*:\s*([^;]+);', re.IGNORECASE)


@dataclass
class SuricataRule:
    raw: str
    action: str = "alert"
    protocol: str = ""
    src_ip: str = ""
    src_port: str = ""
    direction: str = "->"
    dst_ip: str = ""
    dst_port: str = ""
    sid: int = 0
    rev: int = 1
    gid: int = 1
    msg: str = ""
    classtype: str = ""
    severity: str = ""
    reference: List[str] = field(default_factory=list)
    content_patterns: List[str] = field(default_factory=list)
    pcre_patterns: List[str] = field(default_factory=list)
    metadata: Dict[str, str] = field(default_factory=dict)
    flow: str = ""
    flowbits: List[str] = field(default_factory=list)
    threshold: Optional[Dict] = None
    priority: int = 3


class SuricataRuleParser:
    """Parse Suricata .rules format and produce structured rule objects."""

    RULE_PATTERN = re.compile(
        r'^(#\s*)?'
        r'(?P<action>alert|drop|reject|rejectsrc|rejectdst|rejectboth|pass|log)\s+'
        r'(?P<protocol>ip|tcp|udp|icmp|http|ftp|tls|smb|dns|ssh|imap|any)\s+'
        r'(?P<src_ip>[^\s]+)\s+'
        r'(?P<src_port>[^\s]+)\s+'
        r'(?P<direction>->|<>)\s+'
        r'(?P<dst_ip>[^\s]+)\s+'
        r'(?P<dst_port>[^\s]+)\s*'
        r'\((?P<options>.+)\)\s*$',
        re.IGNORECASE,
    )

    def parse_rule(self, line: str) -> Optional[SuricataRule]:
        line = line.strip()
        if not line or line.startswith('#'):
            return None

        m = self.RULE_PATTERN.match(line)
        if not m:
            return None

        rule = SuricataRule(
            raw=line,
            action=m.group("action").lower(),
            protocol=m.group("protocol").lower(),
            src_ip=m.group("src_ip"),
            src_port=m.group("src_port"),
            direction=m.group("direction"),
            dst_ip=m.group("dst_ip"),
            dst_port=m.group("dst_port"),
        )

        options = m.group("options")
        rule.priority = ACTION_MAP.get(rule.action, 1)

        self._parse_options(options, rule)
        self._compute_severity(rule)

        return rule

    def parse_rules(self, rules_text: str) -> List[SuricataRule]:
        parsed = []
        for line in rules_text.split('\n'):
            rule = self.parse_rule(line)
            if rule:
                parsed.append(rule)
        return parsed

    def _parse_options(self, options: str, rule: SuricataRule):
        for meta_match in META_PATTERN.finditer(options):
            key = meta_match.group(1).strip().lower()
            val = meta_match.group(2).strip().rstrip(';')

            if key == "msg":
                rule.msg = val.strip('"')
            elif key == "sid":
                try:
                    rule.sid = int(val)
                except ValueError:
                    pass
            elif key == "rev":
                try:
                    rule.rev = int(val)
                except ValueError:
                    pass
            elif key == "gid":
                try:
                    rule.gid = int(val)
                except ValueError:
                    pass
            elif key == "classtype":
                rule.classtype = val.strip('"').lower()
            elif key == "reference":
                ref_parts = val.split(",", 1)
                if len(ref_parts) == 2:
                    rule.reference.append(f"{ref_parts[0].strip()}:{ref_parts[1].strip()}")
            elif key == "metadata":
                for mk, mv in [p.split(None, 1) for p in val.split(",") if p.strip()]:
                    rule.metadata[mk.strip()] = mv.strip().strip('"')
            elif key == "priority":
                try:
                    rule.priority = int(val)
                except ValueError:
                    pass
            elif key == "flow":
                rule.flow = val
            elif key == "flowbits":
                rule.flowbits = [fb.strip() for fb in val.split(",")]
            elif key == "threshold":
                rule.threshold = self._parse_threshold(val)

        for content_match in CONTENT_PATTERN.finditer(options):
            rule.content_patterns.append(content_match.group(1))

        for pcre_match in PCRE_PATTERN.finditer(options):
            rule.pcre_patterns.append(pcre_match.group(1))

    def _parse_threshold(self, val: str) -> Dict:
        result = {}
        for k in ("type", "track", "count", "seconds"):
            m = re.search(rf'{k}\s+([^,;]+)', val, re.IGNORECASE)
            if m:
                v = m.group(1).strip().strip('"')
                try:
                    result[k] = int(v)
                except ValueError:
                    result[k] = v
        return result

    def _compute_severity(self, rule: SuricataRule):
        if rule.classtype in CLASS_TYPE_SEVERITY:
            rule.severity = CLASS_TYPE_SEVERITY[rule.classtype]
        elif rule.priority <= 1:
            rule.severity = "critical"
        elif rule.priority == 2:
            rule.severity = "high"
        elif rule.priority == 3:
            rule.severity = "medium"
        else:
            rule.severity = "low"


class SuricataEngine:
    """Convert parsed Suricata rules into OpenSearch queries and evaluate them."""

    def __init__(self, parser: Optional[SuricataRuleParser] = None):
        self.parser = parser or SuricataRuleParser()

    def to_opensearch_query(self, rule: SuricataRule) -> Dict[str, Any]:
        """Convert a Suricata rule into an OpenSearch query DSL."""
        must = []
        should = []

        if rule.protocol and rule.protocol != "any":
            must.append({"term": {"protocol": rule.protocol}})

        for content in rule.content_patterns:
            should.append({"match_phrase": {"message": content}})
            should.append({"match_phrase": {"raw_message": content}})
            should.append({"wildcard": {"data": f"*{self._escape_wildcard(content)}*"}})

        if rule.src_ip and rule.src_ip not in ("$HOME_NET", "$EXTERNAL_NET", "any"):
            cidr = rule.src_ip
            must.append({"term": {"source_ip": cidr}} if "/" not in cidr
                        else {"prefix": {"source_ip": cidr.split("/")[0]}})

        if rule.dst_ip and rule.dst_ip not in ("$HOME_NET", "$EXTERNAL_NET", "any"):
            cidr = rule.dst_ip
            must.append({"term": {"destination_ip": cidr}} if "/" not in cidr
                        else {"prefix": {"destination_ip": cidr.split("/")[0]}})

        if rule.src_port and rule.src_port != "any":
            try:
                must.append({"term": {"src_port": int(rule.src_port)}})
            except ValueError:
                pass

        if rule.dst_port and rule.dst_port != "any":
            try:
                must.append({"term": {"dst_port": int(rule.dst_port)}})
            except ValueError:
                pass

        query = {"bool": {}}
        if must:
            query["bool"]["must"] = must
        if should:
            query["bool"]["should"] = should
            query["bool"]["minimum_should_match"] = 1
        if not must and not should:
            query = {"match_all": {}}

        return query

    def evaluate_rules(self, rules: List[SuricataRule], events: List[Dict]) -> List[Dict]:
        """Client-side evaluation of rules against events (for testing/linting)."""
        results = []
        for rule in rules:
            matches = []
            for event in events:
                if self._rule_matches_event(rule, event):
                    matches.append(event)
            if matches:
                results.append({
                    "sid": rule.sid,
                    "msg": rule.msg,
                    "action": rule.action,
                    "severity": rule.severity,
                    "classtype": rule.classtype,
                    "matches": len(matches),
                    "sample": matches[:3],
                })
        return results

    def _rule_matches_event(self, rule: SuricataRule, event: Dict) -> bool:
        event_str = str(event).lower()

        if rule.content_patterns:
            if not any(c.lower() in event_str for c in rule.content_patterns):
                return False

        if rule.protocol and rule.protocol != "any":
            proto = str(event.get("protocol", event.get("proto", ""))).lower()
            if proto and proto != rule.protocol:
                return False

        src_ip = str(event.get("source_ip", event.get("src_ip", "")))
        if rule.src_ip not in ("$HOME_NET", "$EXTERNAL_NET", "any") and src_ip:
            if rule.src_ip not in (src_ip, "any") and "/" not in rule.src_ip:
                return False

        dst_ip = str(event.get("destination_ip", event.get("dest_ip", event.get("dst_ip", ""))))
        if rule.dst_ip not in ("$HOME_NET", "$EXTERNAL_NET", "any") and dst_ip:
            if rule.dst_ip not in (dst_ip, "any") and "/" not in rule.dst_ip:
                return False

        return True

    @staticmethod
    def _escape_wildcard(s: str) -> str:
        return s.replace("*", "\\*").replace("?", "\\?")


suricata_engine = SuricataEngine()
suricata_parser = SuricataRuleParser()
