"""
AEGISX - Sigma Rule Execution Engine
Parses Sigma detection rules, converts to OpenSearch queries,
executes against log data, and creates Alert records.
"""
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select, and_, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import async_session_factory, get_db
from app.models import DetectionRule, Alert, Asset
from app.services.opensearch import get_search_service

logger = logging.getLogger(__name__)

SIGMA_MODIFIERS = {
    "contains", "startswith", "endswith", "re", "regex",
    "all", "cidr", "base64", "base64offset",
    "gt", "gte", "lt", "lte",
}


def _parse_field_key(field_key: str) -> Tuple[str, Optional[str]]:
    """Parse Sigma field key into (base_field, modifier)."""
    if "|" in field_key:
        parts = field_key.split("|")
        base = parts[0]
        mod = parts[1].lower()
        if mod in SIGMA_MODIFIERS:
            return base, mod
        return field_key, None
    return field_key, None


def _field_to_query_clause(field_name: str, field_value: Any) -> Dict[str, Any]:
    """Convert a Sigma field-value pair into an OpenSearch query clause."""
    base_field, modifier = _parse_field_key(field_name)

    if modifier == "contains":
        return {"wildcard": {base_field: f"*{field_value}*"}}
    elif modifier == "startswith":
        return {"prefix": {base_field: str(field_value)}}
    elif modifier == "endswith":
        return {"wildcard": {base_field: f"*{field_value}"}}
    elif modifier in ("re", "regex"):
        return {"regexp": {base_field: str(field_value)}}
    elif modifier == "all":
        if isinstance(field_value, list):
            clauses = [{"term": {base_field: v}} for v in field_value]
            return {"bool": {"must": clauses}}
        return {"term": {base_field: field_value}}
    elif modifier == "cidr":
        return {"term": {base_field: str(field_value)}}
    elif modifier == "gt":
        return {"range": {base_field: {"gt": field_value}}}
    elif modifier == "gte":
        return {"range": {base_field: {"gte": field_value}}}
    elif modifier == "lt":
        return {"range": {base_field: {"lt": field_value}}}
    elif modifier == "lte":
        return {"range": {base_field: {"lte": field_value}}}
    else:
        if isinstance(field_value, list):
            return {"terms": {base_field: [str(v) for v in field_value]}}
        return {"term": {base_field: str(field_value)}}


def _selection_to_query(selection: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a single Sigma selection dict into a bool must query."""
    if not selection:
        return {"match_all": {}}
    clauses = []
    for field_name, field_value in selection.items():
        clauses.append(_field_to_query_clause(field_name, field_value))
    if len(clauses) == 1:
        return clauses[0]
    return {"bool": {"must": clauses}}


def _parse_condition(
    condition_expr: str,
    selections: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """Parse a Sigma condition expression into OpenSearch query DSL.

    Supports:
    - Simple: "selection" or "sel_1 and sel_2 and sel_3"
    - AND/OR combinations: "sel_1 and (sel_2 or sel_3)"
    - NOT: "sel_1 and not sel_2"
    - 1/all of pattern: "1 of sel_*" or "all of them"
    """
    expr = condition_expr.strip().lower() if condition_expr else ""

    if not expr or not selections:
        if selections:
            all_queries = [_selection_to_query(s) for s in selections.values()]
            return {"bool": {"must": all_queries}}
        return {"match_all": {}}

    if expr == "none":
        return {"match_none": {}}

    _all_of_pattern = re.compile(r"^all\s+of\s+(.+)$")
    _one_of_pattern = re.compile(r"^1\s+of\s+(.+)$")

    all_match = _all_of_pattern.match(expr)
    if all_match:
        target = all_match.group(1).strip()
        query = _build_selection_group_query(target, selections, "must")
        if query:
            return query

    one_match = _one_of_pattern.match(expr)
    if one_match:
        target = one_match.group(1).strip()
        query = _build_selection_group_query(target, selections, "should")
        if query:
            return query

    if expr in selections:
        return _selection_to_query(selections[expr])

    tokens = _tokenize_condition(expr)
    if not tokens:
        return {"match_all": {}}

    return _build_boolean_query(tokens, selections)


def _tokenize_condition(expr: str) -> List[str]:
    """Tokenize condition into list of tokens: identifiers, operators, parens."""
    tokens = []
    i = 0
    current = ""
    while i < len(expr):
        ch = expr[i]
        if ch in ("(", ")"):
            if current.strip():
                tokens.append(current.strip())
                current = ""
            tokens.append(ch)
            i += 1
            continue
        if ch == " " and current.strip():
            tokens.append(current.strip())
            current = ""
            i += 1
            continue
        if ch != " ":
            current += ch
        i += 1
    if current.strip():
        tokens.append(current.strip())
    return tokens


def _build_selection_group_query(
    target: str, selections: Dict[str, Dict[str, Any]], bool_type: str
) -> Optional[Dict[str, Any]]:
    """Resolve 'all of sel_*' or '1 of sel_*' patterns against selection dict."""
    if target in ("them", "themat"):
        queries = [_selection_to_query(s) for s in selections.values()]
    elif target.endswith("*"):
        prefix = target[:-1]
        matched = {k: v for k, v in selections.items() if k.startswith(prefix)}
        if not matched:
            return None
        queries = [_selection_to_query(s) for s in matched.values()]
    elif target in selections:
        return _selection_to_query(selections[target])
    else:
        return None

    if not queries:
        return None

    if len(queries) == 1:
        return queries[0]
    return {"bool": {bool_type: queries}}


def _build_boolean_query(tokens: List[str], selections: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Build a nested boolean query from tokenized condition expression."""
    def parse(index: int) -> Tuple[Optional[Dict[str, Any]], int]:
        must: List[Dict[str, Any]] = []
        must_not: List[Dict[str, Any]] = []
        should: List[Dict[str, Any]] = []
        current_inclusion = "must"

        while index < len(tokens):
            token = tokens[index]

            if token == "(":
                sub_query, index = parse(index + 1)
                if sub_query:
                    if current_inclusion == "must":
                        must.append(sub_query)
                    elif current_inclusion == "must_not":
                        must_not.append(sub_query)
                    else:
                        should.append(sub_query)
                current_inclusion = "must"
                continue

            if token == ")":
                return _assemble_bool(must, must_not, should), index + 1

            if token in ("and", "&&"):
                current_inclusion = "must"
                index += 1
                continue

            if token in ("or", "||"):
                current_inclusion = "should"
                index += 1
                continue

            if token in ("not", "!"):
                current_inclusion = "must_not"
                index += 1
                continue

            token_lower = token.lower() if isinstance(token, str) else token
            if isinstance(token_lower, str) and token_lower in selections:
                query = _selection_to_query(selections[token_lower])
                if current_inclusion == "must":
                    must.append(query)
                elif current_inclusion == "must_not":
                    must_not.append(query)
                else:
                    should.append(query)
            current_inclusion = "must"
            index += 1

        return _assemble_bool(must, must_not, should), index

    def _assemble_bool(m, mn, s):
        parts = {}
        if m:
            parts["must"] = m
        if mn:
            parts["must_not"] = mn
        if s:
            parts["should"] = s
            parts["minimum_should_match"] = 1
        if not parts:
            return {"match_all": {}}
        if len(parts) == 1 and "must" in parts and len(parts["must"]) == 1:
            return parts["must"][0]
        return {"bool": parts}

    result, _ = parse(0)
    return result if result else {"match_all": {}}


def _extract_keywords(rule_content: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract keywords/filters for asset enrichment from rule content."""
    keywords = {}
    if not rule_content:
        return keywords
    detection = rule_content.get("detection", {})
    if not isinstance(detection, dict):
        return keywords
    for key, sel in detection.items():
        if key == "condition" or not isinstance(sel, dict):
            continue
        for field, val in sel.items():
            base, _ = _parse_field_key(field)
            if base in ("host", "hostname", "ComputerName", "computer_name"):
                keywords.setdefault("hostnames", []).append(val)
            elif base in ("SourceIp", "src_ip", "source_ip", "IpAddress"):
                keywords.setdefault("source_ips", []).append(val)
    return keywords


class SigmaEngine:
    """Executes Sigma-formatted detection rules against OpenSearch log data."""

    LOG_INDEX_PREFIX = "aegisx-logs"

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self._search = get_search_service()
        self._log_index = f"{self.LOG_INDEX_PREFIX}-{tenant_id}".lower()

    def evaluate_rule(self, rule: DetectionRule) -> List[dict]:
        """Evaluate a single DetectionRule and return list of matched event dicts."""
        if not rule.rule_content:
            logger.debug("Rule %s has no rule_content, skipping", rule.id)
            return []

        detection = rule.rule_content.get("detection")
        if not detection or not isinstance(detection, dict):
            logger.debug("Rule %s has no valid detection block, skipping", rule.id)
            return []

        condition_expr = detection.get("condition", "")
        selections = {k: v for k, v in detection.items() if k != "condition" and isinstance(v, dict)}

        if not selections:
            logger.debug("Rule %s has no selections, skipping", rule.id)
            return []

        try:
            query = _parse_condition(condition_expr, selections)
        except Exception as e:
            logger.error("Failed to parse condition for rule %s: %s", rule.id, e)
            return []

        logsource = rule.rule_content.get("logsource", {})
        base_query = self._apply_logsource_filter(query, logsource)

        total_matches = 0
        all_matches: List[dict] = []
        page_size = 1000

        try:
            result = self._search.client.search(
                self._log_index,
                base_query,
                from_=0,
                size=page_size,
            )
            hits = result.get("hits", {})
            total_matches = hits.get("total", {}).get("value", 0)
            all_matches = [h.get("_source", {}) for h in hits.get("hits", [])]

            if total_matches > page_size:
                pages = (total_matches + page_size - 1) // page_size
                for p in range(1, pages):
                    result = self._search.client.search(
                        self._log_index,
                        base_query,
                        from_=p * page_size,
                        size=page_size,
                    )
                    hits = result.get("hits", {})
                    all_matches.extend(
                        h.get("_source", {}) for h in hits.get("hits", [])
                    )
        except Exception as e:
            logger.warning(
                "OpenSearch query failed for rule %s on index %s: %s",
                rule.id, self._log_index, e,
            )

        logger.info(
            "Rule '%s' (%s): %d matches found in OpenSearch",
            rule.name, rule.id, total_matches,
        )
        return all_matches

    def _apply_logsource_filter(
        self, query: Dict[str, Any], logsource: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Add logsource-based filters (product, service, category) to the query."""
        if not logsource:
            return query

        filters = []
        product = logsource.get("product")
        service = logsource.get("service")
        category = logsource.get("category")

        if product:
            filters.append({"term": {"event.provider": str(product)}})
        if service:
            filters.append({"term": {"service": str(service)}})
        if category:
            filters.append({"term": {"event.category": str(category)}})

        if not filters:
            return query

        if "bool" in query:
            existing_filter = query["bool"].get("filter", [])
            if isinstance(existing_filter, list):
                query["bool"]["filter"] = existing_filter + filters
            else:
                query["bool"]["filter"] = [existing_filter] + filters if existing_filter else filters
            return query

        return {"bool": {"must": [query], "filter": filters}}

    async def run_all_rules(self) -> Dict[str, Any]:
        """Evaluate all active Sigma rules and create alerts. Returns summary."""
        async with async_session_factory() as db:
            result = await db.execute(
                select(DetectionRule).where(
                    and_(
                        DetectionRule.tenant_id == uuid.UUID(self.tenant_id),
                        DetectionRule.rule_type == "sigma",
                        DetectionRule.status == "active",
                    )
                )
            )
            rules = result.scalars().all()

            if not rules:
                logger.info("No active Sigma rules found for tenant %s", self.tenant_id)
                return {"rules_evaluated": 0, "total_matches": 0, "alerts_created": 0}

            total_matches = 0
            total_alerts = 0
            from app.services.alert_pipeline import AlertPipeline
            from app.services.correlation_engine import CorrelationEngine
            pipeline = AlertPipeline(self.tenant_id, db)
            correlator = CorrelationEngine(self.tenant_id, db)

            for rule in rules:
                try:
                    matches = self.evaluate_rule(rule)
                    if matches:
                        total_matches += len(matches)
                        alerts = await pipeline.generate_alert(rule, matches)
                        total_alerts += len(alerts)
                        for alert in alerts:
                            await correlator.correlate_events(alert)
                        rule.alert_count = (rule.alert_count or 0) + len(alerts)
                        rule.last_triggered = datetime.now(timezone.utc)
                except Exception as e:
                    logger.error("Error evaluating rule %s: %s", rule.id, e, exc_info=True)

            await db.commit()
            logger.info(
                "SigmaEngine run_all_rules complete: %d rules, %d matches, %d alerts",
                len(rules), total_matches, total_alerts,
            )
            return {
                "rules_evaluated": len(rules),
                "total_matches": total_matches,
                "alerts_created": total_alerts,
            }

    async def run_rule_by_id(self, rule_id: str) -> Dict[str, Any]:
        """Evaluate a single rule by ID and create alerts."""
        async with async_session_factory() as db:
            result = await db.execute(
                select(DetectionRule).where(
                    and_(
                        DetectionRule.id == uuid.UUID(rule_id),
                        DetectionRule.tenant_id == uuid.UUID(self.tenant_id),
                    )
                )
            )
            rule = result.scalar_one_or_none()
            if not rule:
                raise ValueError(f"Rule {rule_id} not found for tenant {self.tenant_id}")

            matches = self.evaluate_rule(rule)
            if not matches:
                return {"rule_id": rule_id, "matches": 0, "alerts_created": 0}

            from app.services.alert_pipeline import AlertPipeline
            from app.services.correlation_engine import CorrelationEngine
            pipeline = AlertPipeline(self.tenant_id, db)
            correlator = CorrelationEngine(self.tenant_id, db)

            alerts = await pipeline.generate_alert(rule, matches)
            for alert in await pipeline.generate_alert(rule, matches):
                await correlator.correlate_events(alert)

            rule.alert_count = (rule.alert_count or 0) + len(alerts)
            rule.last_triggered = datetime.now(timezone.utc)
            await db.commit()

            return {
                "rule_id": rule_id,
                "rule_name": rule.name,
                "matches": len(matches),
                "alerts_created": len(alerts),
            }
