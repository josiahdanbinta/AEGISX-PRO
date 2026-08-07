"""IDS/IPS Log Parser - Suricata, Zeek, Snort log ingestion."""
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class IDSEvent:
    timestamp: Optional[datetime] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    signature: Optional[str] = None
    signature_id: Optional[str] = None
    severity: str = "medium"
    category: Optional[str] = None
    action: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None
    source: str = "unknown"


class IDSParser:

    def parse_suricata_eve(self, events: List[Dict[str, Any]]) -> List[IDSEvent]:
        """Parse Suricata EVE JSON format events."""
        parsed = []
        for evt in events:
            try:
                event_type = evt.get('event_type', '')
                e = IDSEvent(source="suricata")
                e.timestamp = datetime.fromisoformat(evt.get('timestamp', '').replace('Z', '+00:00')) if evt.get('timestamp') else None
                e.raw = evt

                if event_type == 'alert':
                    alert = evt.get('alert', {})
                    e.signature = alert.get('signature', '')
                    e.signature_id = str(alert.get('signature_id', ''))
                    e.severity = self._map_suricata_severity(alert.get('severity', 2))
                    e.category = alert.get('category', '')
                    e.action = alert.get('action', '')

                e.src_ip = evt.get('src_ip')
                e.dst_ip = evt.get('dest_ip')
                e.src_port = evt.get('src_port')
                e.dst_port = evt.get('dest_port')
                e.protocol = evt.get('proto', '')
                parsed.append(e)
            except Exception:
                pass
        return parsed

    def parse_zeek_log(self, lines: List[str]) -> List[IDSEvent]:
        """Parse Zeek/Bro TSV log format (header line with #fields)."""
        parsed = []
        header: List[str] = []
        separator = '\t'
        active_sep = '\x09'

        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                if line.startswith('#fields'):
                    header = [f.strip() for f in line[8:].split('\t') if f.strip()]
                elif line.startswith('#separator'):
                    sep = line.split(' ', 1)[1] if ' ' in line else '\t'
                    separator = sep.encode().decode('unicode_escape')
                continue

            if not header:
                continue

            try:
                values = line.split(separator)
                if len(values) != len(header):
                    continue
                fields = dict(zip(header, values))

                e = IDSEvent(source="zeek")
                e.timestamp = datetime.fromtimestamp(float(fields.get('ts', '0'))) if fields.get('ts') else None
                e.src_ip = fields.get('id.orig_h') or fields.get('src')
                e.dst_ip = fields.get('id.resp_h') or fields.get('dst')
                e.src_port = int(fields['id.orig_p']) if fields.get('id.orig_p') and fields['id.orig_p'] != '-' else None
                e.dst_port = int(fields['id.resp_p']) if fields.get('id.resp_p') and fields['id.resp_p'] != '-' else None
                e.protocol = fields.get('proto', '')
                e.signature = fields.get('note', '') or fields.get('name', '')
                e.action = fields.get('actions', '')
                e.raw = fields
                parsed.append(e)
            except Exception:
                pass

        return parsed

    def parse_snort_alert(self, lines: List[str]) -> List[IDSEvent]:
        """Parse Snort alert fast format: timestamp  sig_id  src:port -> dst:port  proto  classification  priority."""
        pattern = re.compile(
            r'(\d{2}/\d{2}(?:/\d{4})?-\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+'
            r'\[\*\*\]\s*\[(\d+:\d+:\d+)\]\s*(.+?)\s*\[\*\*\]\s*'
            r'\[Priority:\s*(\d+)\]\s*'
            r'\{?(\w+)\}?\s*'
            r'(\d+\.\d+\.\d+\.\d+):(\d+)\s*->\s*'
            r'(\d+\.\d+\.\d+\.\d+):(\d+)'
        )
        parsed = []
        for line in lines:
            m = pattern.search(line)
            if m:
                e = IDSEvent(source="snort")
                try:
                    e.timestamp = datetime.strptime(m.group(1), '%m/%d/%Y-%H:%M:%S')
                except ValueError:
                    try:
                        e.timestamp = datetime.strptime(m.group(1), '%m/%d-%H:%M:%S')
                    except ValueError:
                        pass
                e.signature_id = m.group(2)
                e.signature = m.group(3).strip()
                e.severity = self._map_snort_priority(int(m.group(4)))
                e.protocol = m.group(5)
                e.src_ip = m.group(6)
                e.src_port = int(m.group(7))
                e.dst_ip = m.group(8)
                e.dst_port = int(m.group(9))
                e.raw = {"line": line}
                parsed.append(e)
        return parsed

    def _map_suricata_severity(self, sev: int) -> str:
        mapping = {1: "critical", 2: "high", 3: "medium", 4: "low"}
        return mapping.get(sev, "medium")

    def _map_snort_priority(self, priority: int) -> str:
        mapping = {1: "critical", 2: "high", 3: "medium", 4: "low"}
        return mapping.get(priority, "medium")

    def ingest_from_file(self, filepath: str, format: str) -> List[Dict[str, Any]]:
        """Ingest IDS events from a log file."""
        try:
            with open(filepath, 'r') as f:
                content = f.read()

            if format == 'suricata':
                events = []
                for line in content.split('\n'):
                    line = line.strip()
                    if line:
                        try:
                            events.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
                parsed = self.parse_suricata_eve(events)
            elif format == 'zeek':
                parsed = self.parse_zeek_log(content.split('\n'))
            elif format == 'snort':
                parsed = self.parse_snort_alert(content.split('\n'))
            else:
                return []

            return [
                {
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                    "src_ip": e.src_ip,
                    "dst_ip": e.dst_ip,
                    "src_port": e.src_port,
                    "dst_port": e.dst_port,
                    "protocol": e.protocol,
                    "signature": e.signature,
                    "signature_id": e.signature_id,
                    "severity": e.severity,
                    "category": e.category,
                    "action": e.action,
                    "source": e.source,
                }
                for e in parsed
            ]
        except Exception as e:
            return [{"error": str(e)}]
