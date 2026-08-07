# AEGISX PRO — 9-Tier Architecture Gap Analysis

_Generated: 2026-08-07 | Target Architecture: Production-Grade SOC Platform_

## Executive Summary

The existing AEGISX codebase implements a **~40% complete** version of the target 9-tier architecture. Tiers 1, 4, 6, and 7 are well-implemented with production-ready code. Tiers 2, 3, 5, 8, and 9 have major gaps — the infrastructure backbone (event streaming, data lakes, observability) is either missing entirely or uses development-only configurations.

---

## TIER 1: API Gateway & Authentication — 80% Complete

| Feature | Status | Gap Details |
|---------|--------|-------------|
| OAuth 2.0 / SAML 2.0 | PARTIAL | SAML/OIDC/LDAP/Entra ID all implemented but libraries are import-guarded; no SCIM provisioning |
| API Key Management | DONE | SHA-256 hashed, per-tenant + per-user scoped, expiration support |
| Rate Limiting | DONE | Token bucket in Redis; Nginx rate-limit zones; per-endpoint config; `X-RateLimit-*` headers |
| Request Logging | PARTIAL | `RequestLoggingMiddleware` exists as stub (dispatch body is empty); no request body capture |
| TLS 1.3 + mTLS | NOT DONE | OpenSearch uses `verify_certs=False`; no server TLS config; no mTLS for agent communication |

**Required Actions:**
1. Implement `RequestLoggingMiddleware` to capture request/response bodies into audit log
2. Add TLS configuration to FastAPI (uvicorn with SSL certs)
3. Add mTLS support for agent-server channel
4. Implement SCIM user provisioning for SSO

---

## TIER 2: Data Ingestion — 10% Complete

| Feature | Status | Gap Details |
|---------|--------|-------------|
| Kafka Cluster (3-6 nodes) | MISSING | No Kafka anywhere — no topics, no brokers, no producers/consumers in codebase |
| Schema Registry (Avro) | MISSING | No schema management; all data is JSON only |
| Ingestion API | PARTIAL | `ingestion.py` exists (syslog RFC 5424/3164, JSON events, Elastic Beats) but no TLS client cert auth |
| Deduplication Service | MISSING | No Redis bloom filter implementation; no dedup window |

**Required Actions:**
1. Deploy Kafka StatefulSet (3-node minimum) with topics: `events.raw`, `events.normalized`, `alerts.triggered`, `telemetry.agent`
2. Deploy Confluent Schema Registry
3. Add Avro schema definitions for all event types
4. Implement RedisBloom-based deduplication service (1-hour window)
5. Add Kafka producer to ingestion pipeline and agent data flow

---

## TIER 3: Stream Processing — 0% Complete

| Feature | Status | Gap Details |
|---------|--------|-------------|
| Apache Flink (stateful) | MISSING | No Flink cluster — no JobManager, no TaskManager, no jobs |
| Event Normalization | MISSING | Normalization done ad-hoc in API handlers, not as streaming pipeline |
| Enrichment Pipeline | MISSING | TI lookups and asset metadata enrichment happen at detection time, not at ingestion |
| Window Operations | MISSING | No streaming window operations for baselines |
| State Backend (RocksDB) | MISSING | No stateful stream processing |

**Required Actions:**
1. Deploy Flink JobManager + TaskManager StatefulSets (8-16 slots per TM)
2. Implement Flink jobs: RawEventNormalizer, ThreatIntelEnricher, AssetMetadataJoiner, DeduplicationAggregator
3. Configure RocksDB state backend with PostgreSQL checkpoints
4. Implement 5-minute and 1-hour window operations for baseline computation

---

## TIER 4: Analytics & Detection — 70% Complete

| Feature | Status | Gap Details |
|---------|--------|-------------|
| Detection Rules Engine | MOSTLY DONE | Sigma engine (fully functional), YARA engine, correlation engine all working |
| SIEM Correlator | DONE | Graph-based alert correlation with DFS clustering, temporal windows, auto-incident creation |
| UEBA Scorer | STUB | Endpoint exists but returns empty arrays; no real anomaly models |
| Threat Intel Enricher | DONE | MISP/custom feed integration, IOC normalization, confidence scoring |
| Alert Topic Output | MISSING | Alerts written to PostgreSQL; no Kafka alert topic output |

**Required Actions:**
1. Implement real ML anomaly detection (IsolationForest, Autoencoder)
2. Build UEBA scoring profiles with configurable baselines
3. Add Kafka alert topic producer (`alerts.triggered`)
4. Implement Suricata rule evaluation engine (currently string-matching only)
5. Add false-positive feedback loop and rule tuning metrics

---

## TIER 5: Data Storage — 30% Complete

| Feature | Status | Gap Details |
|---------|--------|-------------|
| PostgreSQL (OLTP) | DONE | Full SQLAlchemy 2.0 async with row-level multi-tenancy, connection pooling |
| TimescaleDB | MISSING | Only vanilla PostgreSQL 15; no hypertables, no time-series optimization |
| ClickHouse | MISSING | No columnar analytics database |
| MinIO (S3) | MISSING | File uploads save to local disk (`/app/uploads`); no object storage |
| Redis (Cache) | DONE | Async Redis with CacheService wrapper, rate limiting, session store |

**Required Actions:**
1. Deploy TimescaleDB with hypertables for: `events_raw`, `alerts_created`, `audit_trail`
2. Configure 90-day hot / 7-year cold archive retention policies
3. Deploy ClickHouse cluster for pre-aggregated metrics and analytical queries
4. Deploy MinIO with immutable object locking, versioning, and compliance holds
5. Migrate evidence storage from local disk to MinIO

---

## TIER 6: Application Services — 65% Complete

| Feature | Status | Gap Details |
|---------|--------|-------------|
| SOC API (Case Management) | MOSTLY DONE | Incidents CRUD, timeline, evidence with chain of custody, notes |
| Agent Management Service | PARTIAL | Registration, heartbeat, data push work; missing auto-update, group policy, certificate auth |
| Rules Management Service | PARTIAL | YAML/JSON Sigma ingestion, rule versioning, but no A/B testing (shadow rules) |
| Threat Intel Service | DONE | Feed ingestion, IOC normalization, confidence scoring |

**Required Actions:**
1. Implement agent auto-update mechanism with version comparison
2. Add agent group/policy management
3. Implement shadow rule A/B testing (execute rules without generating alerts)
4. Add agent-to-server certificate-based authentication

---

## TIER 7: Frontend & Dashboards — 60% Complete

| Feature | Status | Gap Details |
|---------|--------|-------------|
| Real-time Alert Dashboard | PARTIAL | 30-second HTTP polling, not true WebSocket push |
| Case Management Workbench | PARTIAL | Basic CRUD + timeline + notes; no task/checklist, SLA timers, drag-drop playbooks |
| Threat Hunting Interface | MISSING | No IOC pivot, no query language (KQL/SPL), no hunt playbooks |
| SOAR Playbook Builder | PARTIAL | Form-based CRUD only; no visual node editor, no drag-and-drop, no branching visualization |
| Admin Panels | DONE | Users, Tenants, Audit Logs, Settings all present |
| Dark Theme | DONE | Full dark mode with `dark:` Tailwind classes throughout |
| Accessibility (WCAG 2.1 AA) | PARTIAL | Basic aria-labels; missing focus indicators, aria-live regions, skip-to-content, color contrast verification |

**Required Actions:**
1. Implement true WebSocket connections for live dashboard updates
2. Build visual SOAR playbook builder (node-based, drag-and-drop, branching)
3. Create threat hunting interface with query builder and saved hunt playbooks
4. Add SLA timers and task checklists to incident case management
5. Achieve WCAG 2.1 Level AA compliance

---

## TIER 8: Orchestration & Deployment — 35% Complete

| Feature | Status | Gap Details |
|---------|--------|-------------|
| Kubernetes (1.28+) | PARTIAL | Helm chart exists but all stateful services use `Deployment` (not `StatefulSet`) |
| StatefulSets | MISSING | No StatefulSets anywhere; PostgreSQL, Redis, OpenSearch, RabbitMQ all use Deployment |
| Helm Charts (Production) | PARTIAL | Core services covered; missing Kafka, Flink, TSDB, ClickHouse, MinIO, Prometheus, Grafana, Jaeger |
| Docker Images (<200MB) | PARTIAL | Multi-stage builds exist but sizes not verified |
| GitOps (ArgoCD) | MISSING | No ArgoCD Application manifests or configuration |

**Required Actions:**
1. Convert PostgreSQL, Redis, OpenSearch, RabbitMQ from Deployment to StatefulSet
2. Add Helm templates for all new services (Kafka, Flink, TSDB, ClickHouse, MinIO, Prometheus, Grafana, Jaeger)
3. Add ArgoCD ApplicationSet or Application manifests
4. Add PodDisruptionBudgets for all components
5. Implement External Secrets Operator integration

---

## TIER 9: Monitoring & Observability — 10% Complete

| Feature | Status | Gap Details |
|---------|--------|-------------|
| Prometheus | STUB | `monitoring.prometheus.enabled: false` in values.yaml; no Prometheus deployment; no ServiceMonitor |
| Grafana Dashboards | MISSING | No Grafana deployment, no dashboards, no datasource configuration |
| ELK Stack | PARTIAL | OpenSearch deployed (single-node with emptyDir, not StatefulSet); no Kibana/OpenSearch Dashboards; no Logstash |
| Tracing (Jaeger) | MISSING | No Jaeger deployment, no tracing instrumentation |

**Required Actions:**
1. Deploy Prometheus + ServiceMonitor for all services (15s scrape interval)
2. Deploy Grafana with pre-built dashboards (platform health, per-tenant metrics, analyst workload)
3. Convert OpenSearch to StatefulSet with PVCs + deploy OpenSearch Dashboards
4. Deploy Jaeger all-in-one for distributed tracing (10% sample rate)
5. Add Logstash pipeline for log aggregation

---

## Priority Matrix

| Priority | Tier | Component | Effort | Impact |
|----------|------|-----------|--------|--------|
| **P0** | 2 | Kafka Cluster + Topics | High | Critical — event backbone for all tiers |
| **P0** | 8 | StatefulSet conversion (PG, Redis, OS, RMQ) | Medium | Critical — production readiness |
| **P0** | 5 | TimescaleDB for time-series data | Medium | Critical — hypertables needed for event/alerts scale |
| **P1** | 5 | MinIO object storage | Medium | High — evidence/artifact retention |
| **P1** | 9 | Prometheus + Grafana | Medium | High — platform observability |
| **P1** | 3 | Flink stream processing | High | High — real-time enrichment/normalization |
| **P1** | 1 | TLS/mTLS, request logging | Low | High — security compliance |
| **P2** | 5 | ClickHouse analytics | Medium | Medium — analytics performance |
| **P2** | 9 | Jaeger tracing | Low | Medium — debugging/diagnostics |
| **P2** | 7 | WCAG 2.1 AA + visual SOAR builder | High | Medium — UX compliance |
| **P3** | 8 | ArgoCD GitOps | Medium | Low — deployment automation |
| **P3** | 4 | ML anomaly detection | High | Low — UEBA enhancement |

---

## Infrastructure Comparison: Current vs. Target

| Component | Current | Target | Gap Severity |
|-----------|---------|--------|--------------|
| PostgreSQL | Deployment (1 replica, PVC) | StatefulSet (3 replicas, read replicas) | MEDIUM |
| Redis | Deployment (emptyDir, no PVC) | StatefulSet (3 replicas, sentinel, PVC) | HIGH |
| OpenSearch | Deployment (emptyDir, single-node) | StatefulSet (3+ nodes, PVC, dedicated roles) | HIGH |
| RabbitMQ | Deployment (emptyDir) | StatefulSet (3 replicas, PVC, clustering) | HIGH |
| Kafka | Missing | StatefulSet (3-6 brokers, KRaft, PVC) | CRITICAL |
| TimescaleDB | Missing | StatefulSet (3 replicas, hypertables) | CRITICAL |
| ClickHouse | Missing | StatefulSet (2+ shards, replicated) | MEDIUM |
| MinIO | Missing | StatefulSet (4 drives, erasure coding) | HIGH |
| Flink | Missing | Deployment JM + StatefulSet TM | HIGH |
| Prometheus | Missing | StatefulSet (PVC, 15-day retention) | HIGH |
| Grafana | Missing | Deployment (PVC for dashboards) | HIGH |
| Jaeger | Missing | Deployment (all-in-one or Operator) | MEDIUM |
| ArgoCD | Missing | Deployment (Application CR) | LOW |

---

## Migration Path (Recommended Order)

### Phase 1: Infrastructure Foundation (2-3 weeks)
1. Convert PG/Redis/OpenSearch/RabbitMQ to StatefulSets with PVCs
2. Deploy Kafka cluster (3-node minimum) + Schema Registry
3. Deploy MinIO for object storage
4. Deploy Prometheus + Grafana for observability

### Phase 2: Data Pipeline (2-3 weeks)
1. Implement Kafka producers in ingestion pipeline and agent
2. Deploy Flink cluster with normalization/enrichment jobs
3. Deploy TimescaleDB, create hypertables, migrate event data
4. Add deduplication service (RedisBloom)

### Phase 3: Platform Enhancement (3-4 weeks)
1. Deploy ClickHouse for analytical workloads
2. Deploy Jaeger for distributed tracing
3. Implement ArgoCD GitOps
4. Add mTLS and TLS 1.3 across all service-to-service communication

### Phase 4: UX & Detection (3-4 weeks)
1. Build visual SOAR playbook editor
2. Create threat hunting interface
3. Achieve WCAG 2.1 AA compliance
4. Implement ML anomaly detection models
5. Add SIEM rule A/B testing framework
