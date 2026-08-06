"""
AEGISX - OpenSearch Full-Text Search Service
Index management, document search, log analytics
"""
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

from app.core.config import settings

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════
# OpenSearch Client
# ════════════════════════════════════════════════════════════════════

class OpenSearchClient:
    """Thin wrapper around opensearchpy providing index management,
    document CRUD, and full-text search capabilities."""

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        use_ssl: Optional[bool] = None,
        index_prefix: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 3,
    ):
        self.host = host or settings.OPENSEARCH_HOST
        self.port = port or settings.OPENSEARCH_PORT
        self.user = user or settings.OPENSEARCH_USER
        self.password = password or settings.OPENSEARCH_PASSWORD
        self.use_ssl = use_ssl if use_ssl is not None else settings.OPENSEARCH_USE_SSL
        self.index_prefix = index_prefix or settings.OPENSEARCH_INDEX_PREFIX
        self.timeout = timeout
        self.max_retries = max_retries
        self._client: Optional[Any] = None
        self._connected = False

    @property
    def client(self):
        """Lazy-initialize the OpenSearch client on first access."""
        if self._client is None:
            try:
                from opensearchpy import OpenSearch
                scheme = "https" if self.use_ssl else "http"
                hosts = [{
                    "host": self.host,
                    "port": self.port,
                }]

                self._client = OpenSearch(
                    hosts=hosts,
                    http_compress=True,
                    http_auth=(self.user, self.password),
                    use_ssl=self.use_ssl,
                    verify_certs=False,
                    ssl_assert_hostname=False,
                    ssl_show_warn=False,
                    timeout=self.timeout,
                    max_retries=self.max_retries,
                    retry_on_timeout=True,
                )
                if self._client.ping():
                    self._connected = True
                    logger.info("OpenSearch connected: %s://%s:%s", scheme, self.host, self.port)
                else:
                    logger.warning("OpenSearch ping failed for %s:%s", self.host, self.port)
            except ImportError:
                logger.error("opensearchpy is not installed. Install with: pip install opensearch-py")
                raise
            except Exception as e:
                logger.error("Failed to connect to OpenSearch: %s", e)
                raise
        return self._client

    @property
    def connected(self) -> bool:
        if self._client is None:
            try:
                self.client
            except Exception:
                return False
        return self._connected

    def _build_index_name(self, name: str, tenant_id: Optional[str] = None) -> str:
        if tenant_id:
            return f"{self.index_prefix}-{name}-{tenant_id}".lower()
        return f"{self.index_prefix}-{name}".lower()

    def ping(self) -> bool:
        try:
            return self.client.ping()
        except Exception:
            return False

    # ── Index Management ──────────────────────────────────────────

    def create_index(self, name: str, mappings: Optional[Dict[str, Any]] = None, settings_cfg: Optional[Dict[str, Any]] = None) -> bool:
        body: Dict[str, Any] = {}
        if settings_cfg:
            body["settings"] = settings_cfg
        else:
            body["settings"] = {
                "index": {
                    "number_of_shards": 1,
                    "number_of_replicas": 1,
                    "refresh_interval": "5s",
                }
            }
        if mappings:
            body["mappings"] = mappings

        try:
            self.client.indices.create(index=name, body=body)
            logger.info("Index '%s' created", name)
            return True
        except Exception as e:
            logger.error("Failed to create index '%s': %s", name, e)
            return False

    def delete_index(self, name: str) -> bool:
        try:
            self.client.indices.delete(index=name, ignore=[404])
            logger.info("Index '%s' deleted", name)
            return True
        except Exception as e:
            logger.error("Failed to delete index '%s': %s", name, e)
            return False

    def index_exists(self, name: str) -> bool:
        try:
            return self.client.indices.exists(index=name)
        except Exception:
            return False

    def list_indices(self, pattern: str = "*") -> List[str]:
        try:
            return list(self.client.indices.get(index=pattern).keys())
        except Exception:
            return []

    def get_mapping(self, name: str) -> Optional[Dict[str, Any]]:
        try:
            result = self.client.indices.get_mapping(index=name)
            return result.get(name, {}).get("mappings", {})
        except Exception:
            return None

    def refresh_index(self, name: str):
        try:
            self.client.indices.refresh(index=name)
        except Exception:
            pass

    # ── Document Operations ───────────────────────────────────────

    def index_document(
        self,
        index: str,
        doc_id: Optional[str],
        document: Dict[str, Any],
        refresh: bool = False,
    ) -> Optional[str]:
        try:
            result = self.client.index(
                index=index,
                id=doc_id,
                body=document,
                refresh=refresh,
            )
            return result.get("_id")
        except Exception as e:
            logger.error("Failed to index document in '%s': %s", index, e)
            return None

    def bulk_index(
        self,
        index: str,
        documents: List[Tuple[Optional[str], Dict[str, Any]]],
        chunk_size: int = 500,
        refresh: bool = False,
    ) -> Tuple[int, int]:
        """Bulk index documents. Returns (success_count, error_count)."""
        if not documents:
            return 0, 0
        try:
            from opensearchpy import helpers

            actions = [
                {
                    "_index": index,
                    "_id": doc_id,
                    "_source": doc,
                }
                for doc_id, doc in documents
            ]
            success, errors = helpers.bulk(
                self.client,
                actions,
                chunk_size=chunk_size,
                refresh=refresh,
                stats_only=True,
                raise_on_error=False,
            )
            if errors:
                logger.warning("Bulk index to '%s': %d docs, %d errors", index, len(documents) - errors, errors)
            return max(0, len(documents) - errors), errors
        except Exception as e:
            logger.error("Bulk index failed for '%s': %s", index, e)
            return 0, len(documents)

    def get_document(self, index: str, doc_id: str) -> Optional[Dict[str, Any]]:
        try:
            result = self.client.get(index=index, id=doc_id)
            return result.get("_source")
        except Exception:
            return None

    def update_document(
        self,
        index: str,
        doc_id: str,
        partial_doc: Dict[str, Any],
        refresh: bool = False,
    ) -> bool:
        try:
            self.client.update(index=index, id=doc_id, body={"doc": partial_doc}, refresh=refresh)
            return True
        except Exception as e:
            logger.error("Failed to update document '%s' in '%s': %s", doc_id, index, e)
            return False

    def delete_document(self, index: str, doc_id: str, refresh: bool = False) -> bool:
        try:
            self.client.delete(index=index, id=doc_id, refresh=refresh, ignore=[404])
            return True
        except Exception as e:
            logger.error("Failed to delete document '%s' from '%s': %s", doc_id, index, e)
            return False

    # ── Search ────────────────────────────────────────────────────

    def search(
        self,
        index: str,
        query_dsl: Dict[str, Any],
        from_: int = 0,
        size: int = 20,
        sort: Optional[List[Dict[str, Any]]] = None,
        source_fields: Optional[List[str]] = None,
        aggregations: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {"query": query_dsl}
        if sort:
            body["sort"] = sort
        if aggregations:
            body["aggs"] = aggregations

        kwargs: Dict[str, Any] = {
            "index": index,
            "body": body,
            "from_": from_,
            "size": size,
        }
        if source_fields is not None:
            kwargs["_source"] = source_fields

        try:
            return self.client.search(**kwargs)
        except Exception as e:
            logger.error("Search failed on '%s': %s", index, e)
            return {"hits": {"total": {"value": 0}, "hits": []}}

    def count(self, index: str, query_dsl: Optional[Dict[str, Any]] = None) -> int:
        try:
            body = {"query": query_dsl} if query_dsl else {}
            result = self.client.count(index=index, body=body)
            return result.get("count", 0)
        except Exception:
            return 0

    def delete_by_query(self, index: str, query_dsl: Dict[str, Any]) -> int:
        try:
            result = self.client.delete_by_query(index=index, body={"query": query_dsl})
            return result.get("deleted", 0)
        except Exception:
            return 0


# ════════════════════════════════════════════════════════════════════
# Index Mapping Definitions
# ════════════════════════════════════════════════════════════════════

LOGS_MAPPING = {
    "properties": {
        "id": {"type": "keyword"},
        "tenant_id": {"type": "keyword"},
        "timestamp": {"type": "date"},
        "level": {"type": "keyword"},
        "source": {"type": "keyword"},
        "service": {"type": "keyword"},
        "host": {"type": "keyword"},
        "message": {
            "type": "text",
            "analyzer": "standard",
            "fields": {"keyword": {"type": "keyword", "ignore_above": 512}},
        },
        "raw_log": {
            "type": "text",
            "analyzer": "standard",
        },
        "event_type": {"type": "keyword"},
        "process_name": {"type": "keyword"},
        "process_id": {"type": "integer"},
        "username": {"type": "keyword"},
        "ip_address": {"type": "ip"},
        "source_ip": {"type": "ip"},
        "destination_ip": {"type": "ip"},
        "port": {"type": "integer"},
        "user_agent": {"type": "text"},
        "tags": {"type": "keyword"},
        "metadata": {"type": "object", "enabled": True},
    },
}

ALERTS_MAPPING = {
    "properties": {
        "id": {"type": "keyword"},
        "tenant_id": {"type": "keyword"},
        "title": {
            "type": "text",
            "analyzer": "standard",
            "fields": {"keyword": {"type": "keyword", "ignore_above": 512}},
        },
        "description": {"type": "text", "analyzer": "standard"},
        "severity": {"type": "keyword"},
        "status": {"type": "keyword"},
        "rule_id": {"type": "keyword"},
        "rule_name": {"type": "keyword"},
        "source_ip": {"type": "ip"},
        "destination_ip": {"type": "ip"},
        "asset_id": {"type": "keyword"},
        "asset_name": {"type": "keyword"},
        "triggered_at": {"type": "date"},
        "acknowledged_at": {"type": "date"},
        "resolved_at": {"type": "date"},
        "assigned_to": {"type": "keyword"},
        "tags": {"type": "keyword"},
        "evidence": {"type": "object", "enabled": True},
        "created_at": {"type": "date"},
    },
}

INCIDENTS_MAPPING = {
    "properties": {
        "id": {"type": "keyword"},
        "tenant_id": {"type": "keyword"},
        "title": {
            "type": "text",
            "analyzer": "standard",
            "fields": {"keyword": {"type": "keyword", "ignore_above": 512}},
        },
        "description": {"type": "text", "analyzer": "standard"},
        "severity": {"type": "keyword"},
        "status": {"type": "keyword"},
        "priority": {"type": "keyword"},
        "assignee_id": {"type": "keyword"},
        "assignee_name": {"type": "keyword"},
        "mitre_tactics": {"type": "keyword"},
        "mitre_techniques": {"type": "keyword"},
        "tags": {"type": "keyword"},
        "timeline": {
            "type": "nested",
            "properties": {
                "timestamp": {"type": "date"},
                "action": {"type": "keyword"},
                "description": {"type": "text"},
                "performed_by": {"type": "keyword"},
            },
        },
        "notes": {
            "type": "nested",
            "properties": {
                "timestamp": {"type": "date"},
                "content": {"type": "text"},
                "author": {"type": "keyword"},
            },
        },
        "created_at": {"type": "date"},
        "updated_at": {"type": "date"},
        "resolved_at": {"type": "date"},
    },
}

ASSETS_MAPPING = {
    "properties": {
        "id": {"type": "keyword"},
        "tenant_id": {"type": "keyword"},
        "name": {
            "type": "text",
            "analyzer": "standard",
            "fields": {"keyword": {"type": "keyword", "ignore_above": 512}},
        },
        "hostname": {"type": "keyword"},
        "ip_address": {"type": "ip"},
        "mac_address": {"type": "keyword"},
        "asset_type": {"type": "keyword"},
        "os": {"type": "keyword"},
        "os_version": {"type": "keyword"},
        "status": {"type": "keyword"},
        "group_id": {"type": "keyword"},
        "group_name": {"type": "keyword"},
        "tags": {"type": "keyword"},
        "risk_score": {"type": "float"},
        "critically": {"type": "keyword"},
        "last_seen": {"type": "date"},
        "first_seen": {"type": "date"},
        "created_at": {"type": "date"},
        "vulnerabilities_count": {"type": "integer"},
        "open_incidents_count": {"type": "integer"},
    },
}

INDEX_MAPPINGS = {
    "logs": LOGS_MAPPING,
    "alerts": ALERTS_MAPPING,
    "incidents": INCIDENTS_MAPPING,
    "assets": ASSETS_MAPPING,
}


# ════════════════════════════════════════════════════════════════════
# Search Service
# ════════════════════════════════════════════════════════════════════

class SearchService:
    """High-level search operations combining the OpenSearch client with
    tenant-scoped index management."""

    def __init__(self, client: Optional[OpenSearchClient] = None):
        self._client = client

    @property
    def client(self) -> OpenSearchClient:
        if self._client is None:
            self._client = get_opensearch()
        return self._client

    def _index_for(self, resource: str, tenant_id: Optional[str] = None) -> str:
        """Build tenant-scoped index name: aegisx-logs-{tenant_id}"""
        return self.client._build_index_name(resource, tenant_id)

    # ── Index Lifecycle ───────────────────────────────────────────

    def ensure_index(self, resource: str, tenant_id: str) -> bool:
        index_name = self._index_for(resource, tenant_id)
        if self.client.index_exists(index_name):
            return True
        mapping = INDEX_MAPPINGS.get(resource)
        if not mapping:
            mapping = {
                "properties": {
                    "id": {"type": "keyword"},
                    "tenant_id": {"type": "keyword"},
                    "created_at": {"type": "date"},
                },
            }
        return self.client.create_index(index_name, mappings=mapping)

    def ensure_all_indexes(self, tenant_id: str) -> Dict[str, bool]:
        return {res: self.ensure_index(res, tenant_id) for res in INDEX_MAPPINGS}

    def reindex_all(self, tenant_id: str) -> Dict[str, bool]:
        """Delete and recreate all indexes for a tenant."""
        results = {}
        for resource in INDEX_MAPPINGS:
            name = self._index_for(resource, tenant_id)
            self.client.delete_index(name)
            results[resource] = self.ensure_index(resource, tenant_id)
        return results

    # ── Full-Text Search ──────────────────────────────────────────

    def full_text_search(
        self,
        index: str,
        query: str,
        filters: Optional[Dict[str, Any]] = None,
        from_: int = 0,
        size: int = 20,
        highlight_fields: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Full-text search with optional filters across any index."""
        query_dsl: Dict[str, Any] = {
            "bool": {
                "must": [
                    {
                        "multi_match": {
                            "query": query,
                            "fields": ["*"],
                            "type": "best_fields",
                            "fuzziness": "AUTO",
                            "operator": "or",
                        },
                    },
                ],
            },
        }

        if filters:
            filter_clauses = []
            for field, value in filters.items():
                if isinstance(value, list):
                    filter_clauses.append({"terms": {field: value}})
                elif isinstance(value, dict):
                    filter_clauses.append({"range": {field: value}})
                else:
                    filter_clauses.append({"term": {field: value}})
            if filter_clauses:
                query_dsl["bool"]["filter"] = filter_clauses

        search_body: Dict[str, Any] = {"query": query_dsl}
        if highlight_fields:
            search_body["highlight"] = {
                "fields": {f: {} for f in highlight_fields},
                "pre_tags": ["<em>"],
                "post_tags": ["</em>"],
            }

        return self.client.search(index, query_dsl, from_=from_, size=size)

    # ── Log Aggregation ───────────────────────────────────────────

    def aggregate_logs(
        self,
        index: str,
        field: str,
        time_range: Optional[Dict[str, Any]] = None,
        size: int = 20,
    ) -> Dict[str, Any]:
        query_dsl: Dict[str, Any] = {"match_all": {}}
        if time_range:
            query_dsl = {
                "bool": {
                    "must": [{"match_all": {}}],
                    "filter": [
                        {"range": {"timestamp": time_range}},
                    ],
                },
            }

        aggs = {
            f"by_{field}": {
                "terms": {
                    "field": field,
                    "size": size,
                    "order": {"_count": "desc"},
                },
            },
        }

        result = self.client.search(index, query_dsl, size=0, aggregations=aggs)
        return result.get("aggregations", {}).get(f"by_{field}", {}).get("buckets", [])

    # ── Autocomplete ──────────────────────────────────────────────

    def suggest(
        self,
        index: str,
        prefix: str,
        field: str = "name",
        size: int = 10,
    ) -> List[str]:
        query_body = {
            "suggest": {
                f"{field}_suggest": {
                    "prefix": prefix,
                    "completion": {
                        "field": f"{field}.suggest",
                        "size": size,
                        "skip_duplicates": True,
                    },
                },
            },
        }
        try:
            result = self.client.client.search(index=index, body=query_body)
            suggestions = result.get("suggest", {}).get(f"{field}_suggest", [])
            if suggestions:
                return [
                    opt["text"]
                    for opt in suggestions[0].get("options", [])
                ]
        except Exception:
            pass
        return []

    # ── Index Document Helpers ────────────────────────────────────

    def index_alert(self, alert_data: Dict[str, Any], tenant_id: str) -> Optional[str]:
        self.ensure_index("alerts", tenant_id)
        idx = self._index_for("alerts", tenant_id)
        return self.client.index_document(idx, alert_data.get("id"), alert_data)

    def index_incident(self, incident_data: Dict[str, Any], tenant_id: str) -> Optional[str]:
        self.ensure_index("incidents", tenant_id)
        idx = self._index_for("incidents", tenant_id)
        return self.client.index_document(idx, incident_data.get("id"), incident_data)

    def index_asset(self, asset_data: Dict[str, Any], tenant_id: str) -> Optional[str]:
        self.ensure_index("assets", tenant_id)
        idx = self._index_for("assets", tenant_id)
        return self.client.index_document(idx, asset_data.get("id"), asset_data)

    def index_log(self, log_data: Dict[str, Any], tenant_id: str) -> Optional[str]:
        self.ensure_index("logs", tenant_id)
        idx = self._index_for("logs", tenant_id)
        return self.client.index_document(idx, log_data.get("id"), log_data)

    def bulk_index_logs(self, logs: List[Dict[str, Any]], tenant_id: str) -> Tuple[int, int]:
        self.ensure_index("logs", tenant_id)
        idx = self._index_for("logs", tenant_id)
        docs = [(d.get("id"), d) for d in logs]
        return self.client.bulk_index(idx, docs)


# ════════════════════════════════════════════════════════════════════
# Lazy Singleton
# ════════════════════════════════════════════════════════════════════

_opensearch_client: Optional[OpenSearchClient] = None
_search_service: Optional[SearchService] = None


def get_opensearch() -> OpenSearchClient:
    """Lazy singleton for the OpenSearch client."""
    global _opensearch_client
    if _opensearch_client is None:
        _opensearch_client = OpenSearchClient()
    return _opensearch_client


def get_search_service() -> SearchService:
    """Lazy singleton for the SearchService."""
    global _search_service
    if _search_service is None:
        _search_service = SearchService()
    return _search_service


def reset_opensearch():
    """Reset the global client (useful for testing)."""
    global _opensearch_client, _search_service
    _opensearch_client = None
    _search_service = None
