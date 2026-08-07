"""
AEGISX - Rule Watcher Service
ConfigMap-based hot-reload of detection rules. Watches for changes
in Kubernetes ConfigMaps and reloads Sigma/Falco rules without restart.
"""
import asyncio
import hashlib
import json
import logging
import os
import time
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

RULES_DIR = os.environ.get("AEGISX_RULES_DIR", "/etc/aegisx/rules")
CHECK_INTERVAL = int(os.environ.get("AEGISX_RULES_CHECK_INTERVAL", "30"))


class RuleWatcher:
    """
    Watches a directory or ConfigMap mount for detection rule changes.
    Supports Sigma YAML, Sigma JSON, and Falco-style rules.
    Hot-reloads rules without restarting the application.
    """

    def __init__(self, rules_dir: Optional[str] = None):
        self.rules_dir = rules_dir or RULES_DIR
        self._rule_hashes: Dict[str, str] = {}
        self._rules: Dict[str, Dict[str, Any]] = {}
        self._callbacks: List[Callable] = []
        self._running = False
        self._stats = {
            "total_rules": 0,
            "last_reload": None,
            "reloads": 0,
            "errors": 0,
        }

    def on_reload(self, callback: Callable[[List[Dict[str, Any]]], None]):
        self._callbacks.append(callback)

    async def start(self):
        if not os.path.isdir(self.rules_dir):
            os.makedirs(self.rules_dir, exist_ok=True)
            logger.warning("Rules directory %s created (empty). Mount ConfigMap here.", self.rules_dir)

        self._running = True
        await self._scan_once()
        logger.info("Rule watcher started. Watching %s", self.rules_dir)

        while self._running:
            await asyncio.sleep(CHECK_INTERVAL)
            await self._scan_once()

    async def _scan_once(self):
        try:
            changed = False
            current_files: Set[str] = set()

            for root, dirs, files in os.walk(self.rules_dir):
                for fname in sorted(files):
                    if fname.startswith(".") or fname.startswith(".."):
                        continue
                    fpath = os.path.join(root, fname)
                    current_files.add(fpath)

            removed = set(self._rule_hashes.keys()) - current_files
            for fpath in removed:
                logger.info("Rule removed: %s", fpath)
                rule_id = os.path.basename(fpath)
                self._rule_hashes.pop(fpath, None)
                self._rules.pop(rule_id, None)
                changed = True

            for fpath in current_files:
                try:
                    with open(fpath, "r") as f:
                        content = f.read()
                    file_hash = hashlib.sha256(content.encode()).hexdigest()

                    if self._rule_hashes.get(fpath) == file_hash:
                        continue

                    self._rule_hashes[fpath] = file_hash
                    rules = self._parse_rule_file(fpath, content)
                    for rule in rules:
                        rule_id = rule.get("rule_id", os.path.basename(fpath))
                        self._rules[rule_id] = rule
                    changed = True
                    logger.info("Rule loaded/reloaded: %s (%d rules)", fpath, len(rules))

                except Exception as e:
                    self._stats["errors"] += 1
                    logger.error("Failed to parse rule %s: %s", fpath, e)

            if changed:
                self._stats["reloads"] += 1
                self._stats["total_rules"] = len(self._rules)
                self._stats["last_reload"] = time.time()

                rules_list = [{"rule_id": k, **v} for k, v in self._rules.items()]
                for cb in self._callbacks:
                    try:
                        cb(rules_list)
                    except Exception as e:
                        logger.error("Rule reload callback error: %s", e)

        except Exception as e:
            self._stats["errors"] += 1
            logger.error("Rule watcher scan error: %s", e)

    def _parse_rule_file(self, fpath: str, content: str) -> List[Dict[str, Any]]:
        ext = os.path.splitext(fpath)[1].lower()

        if ext in (".yaml", ".yml"):
            import yaml
            try:
                parsed = yaml.safe_load(content)
            except Exception:
                parsed = self._parse_multi_yaml(content)

            if isinstance(parsed, list):
                rules = []
                for item in parsed:
                    if isinstance(item, dict):
                        rules.extend(self._normalize_yaml_rule(item))
                return rules
            elif isinstance(parsed, dict):
                return self._normalize_yaml_rule(parsed)

        elif ext == ".json":
            parsed = json.loads(content)
            if isinstance(parsed, list):
                return [{"rule_id": r.get("id", ""), **r} for r in parsed if isinstance(r, dict)]
            elif isinstance(parsed, dict):
                return [{"rule_id": parsed.get("id", ""), **parsed}]

        elif ext in (".sigma",):
            return self._parse_sigma_rule(content)

        elif ext in (".falco", ".yara"):
            return [{"rule_id": os.path.basename(fpath), "type": ext.lstrip("."), "content": content}]

        return []

    def _normalize_yaml_rule(self, rule: Dict[str, Any]) -> List[Dict[str, Any]]:
        rule_id = rule.get("id") or rule.get("title", "").lower().replace(" ", "_")
        rule_type = "sigma" if "detection" in rule else "falco" if "condition" in rule else "custom"

        return [{
            "rule_id": rule_id,
            "type": rule_type,
            "title": rule.get("title", rule_id),
            "description": rule.get("description", ""),
            "severity": rule.get("level", "medium"),
            "enabled": rule.get("status", "stable") != "disabled",
            "tags": rule.get("tags", []),
            "content": rule,
            **({k: v for k, v in rule.items() if k in (
                "detection", "logsource", "condition", "output", "priority",
                "falsepositives", "references", "author", "date", "modified",
            )}),
        }]

    def _parse_multi_yaml(self, content: str) -> List[Dict[str, Any]]:
        docs = []
        for doc in content.split("---"):
            doc = doc.strip()
            if not doc:
                continue
            import yaml
            try:
                parsed = yaml.safe_load(doc)
                if isinstance(parsed, dict):
                    docs.append(parsed)
                elif isinstance(parsed, list):
                    docs.extend(parsed)
            except Exception:
                pass
        return docs if docs else []

    def _parse_sigma_rule(self, content: str) -> List[Dict[str, Any]]:
        import yaml
        try:
            rule = yaml.safe_load(content)
            if not isinstance(rule, dict):
                return []
            return [{
                "rule_id": rule.get("id", rule.get("title", "").lower().replace(" ", "_")),
                "type": "sigma",
                "title": rule.get("title", ""),
                "description": rule.get("description", ""),
                "severity": rule.get("level", "medium"),
                "enabled": rule.get("status", "stable") != "disabled",
                "tags": rule.get("tags", []),
                "content": rule,
                "logsource": rule.get("logsource"),
                "detection": rule.get("detection"),
            }]
        except Exception:
            return []

    def get_all_rules(self) -> List[Dict[str, Any]]:
        return [{"rule_id": k, **v} for k, v in self._rules.items()]

    def get_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        rule = self._rules.get(rule_id)
        if rule:
            return {"rule_id": rule_id, **rule}
        return None

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "rules_dir": self.rules_dir,
            "is_running": self._running,
        }

    def stop(self):
        self._running = False


rule_watcher = RuleWatcher()
