# AEGISX PRO — 9-Tier Architecture

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             TIER 7: FRONTEND & DASHBOARDS                         │
│  React 18 SPA (TypeScript) · Dark Theme · WCAG 2.1 AA                            │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────────────────┐ │
│  │ Alert        │ │ Threat       │ │ SOAR Builder │ │ Admin Panels             │ │
│  │ Dashboard    │ │ Hunting UI   │ │ (drag & drop)│ │ (Users, Tenants, Audit)  │ │
│  │ (WebSocket)  │ │ (saved query)│ │ 14 actions   │ │                          │ │
│  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └────────────┬─────────────┘ │
├─────────┼────────────────┼────────────────┼──────────────────────┼───────────────┤
│         │          TIER 6: APPLICATION SERVICES                    │               │
│         │  FastAPI · Celery Workers · Redis Cache                  │               │
│  ┌──────┴───────┐ ┌──────────────┐ ┌──────────────┐ ┌────────────┴─────────────┐ │
│  │ SOC API      │ │ Agent Mgmt   │ │ Rules Mgmt   │ │ Threat Intel Service     │ │
│  │ Case Mgmt    │ │ Osquery Sched│ │ Sigma/Falco  │ │ MISP / OpenCTI Pipeline  │ │
│  │ Playbook Exec│ │ EDR Commands │ │ Shadow A/B   │ │ VT + AbuseIPDB + Shodan  │ │
│  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └────────────┬─────────────┘ │
├─────────┼────────────────┼────────────────┼──────────────────────┼───────────────┤
│         │          TIER 5: DATA STORAGE                           │               │
│  ┌──────┴───────┐ ┌──────────────┐ ┌──────────────┐ ┌────────────┴─────────────┐ │
│  │ TimescaleDB  │ │ ClickHouse   │ │ MinIO (S3)   │ │ Redis + OpenSearch       │ │
│  │ Hypertables  │ │ Columnar     │ │ Immutable    │ │ Bloom Filter + Cache     │ │
│  │ 90d hot/7yr  │ │ Analytics    │ │ Evidence     │ │ Full-text Search         │ │
│  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └────────────┬─────────────┘ │
├─────────┼────────────────┼────────────────┼──────────────────────┼───────────────┤
│         │          TIER 4: ANALYTICS & DETECTION                  │               │
│  ┌──────┴───────┐ ┌──────────────┐ ┌──────────────┐ ┌────────────┴─────────────┐ │
│  │ Sigma Engine │ │ Falco Rules  │ │ UEBA Scorer  │ │ SIEM Correlator          │ │
│  │ 477-line     │ │ 25 kernel    │ │ Welford Stats│ │ Temporal + Behavioral    │ │
│  │ parser       │ │ rules        │ │ Anomaly Score│ │ Auto-incident creation   │ │
│  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └────────────┬─────────────┘ │
├─────────┼────────────────┼────────────────┼──────────────────────┼───────────────┤
│         │          TIER 3: STREAM PROCESSING                      │               │
│  ┌──────┴─────────────────┴───────┐  ┌────────────────────────────┴─────────────┐ │
│  │ Apache Flink (PyFlink SQL)     │  │ Stream Processor (Python)                 │ │
│  │ 5 jobs: normalize · aggregate  │  │ Normalize · Enrich · Dedup · Window Ops  │ │
│  │ dedup · UEBA · telemetry       │  │ Redis Bloom Filters · 5min/1hr Windows   │ │
│  │ State: RocksDB + PG checkpoints│  │ State: RocksDB Store (SQLite fallback)   │ │
│  └──────────────┬─────────────────┘  └────────────────────────────┬─────────────┘ │
├─────────────────┼─────────────────────────────────────────────────┼───────────────┤
│                 │          TIER 2: DATA INGESTION                 │               │
│  ┌──────────────┴─────────────────┐  ┌────────────────────────────┴─────────────┐ │
│  │ Kafka Cluster (3 brokers)      │  │ Ingestion API                            │ │
│  │ Topics: events.raw · .normalized│  │ POST /batch · /syslog · /json · /beats  │ │
│  │ alerts.triggered · telemetry   │  │ Avro Schema Registry                    │ │
│  │ RF=3 · 7-day retention         │  │ Redis Bloom Dedup (1hr window)          │ │
│  └──────────────┬─────────────────┘  └────────────────────────────┬─────────────┘ │
├─────────────────┼─────────────────────────────────────────────────┼───────────────┤
│                 │          TIER 1: API GATEWAY & AUTH             │               │
│  ┌──────────────┴──────────────────┐ ┌────────────────────────────┴─────────────┐ │
│  │ OAuth 2.0 / SAML 2.0 / OIDC    │ │ TLS 1.3 + mTLS                           │ │
│  │ API Key Management (rotating)   │ │ Nginx Reverse Proxy                     │ │
│  │ Rate Limiting (token bucket)    │ │ Security Headers (CSP, HSTS, XFO)       │ │
│  │ Immutable Audit Log (WORM)      │ │ Hash Chain Integrity Verification       │ │
│  └─────────────────────────────────┘ └──────────────────────────────────────────┘ │
├──────────────────────────────────────────────────────────────────────────────────┤
│                          TIER 9: MONITORING & OBSERVABILITY                       │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────────────────┐ │
│  │ Prometheus   │ │ Grafana      │ │ ELK Stack    │ │ Jaeger Tracing           │ │
│  │ 11 jobs      │ │ 6 dashboards │ │ Logstash pipe│ │ OpenTelemetry 10% sample │ │
│  │ 10 alerts    │ │ platform+    │ │ 30-day retn  │ │ 7-day retention          │ │
│  │ 15s interval │ │ tenant+soc   │ │ Kibana UI    │ │ Rule exec tracing        │ │
│  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────────────────┘ │
├──────────────────────────────────────────────────────────────────────────────────┤
│                         TIER 8: ORCHESTRATION & DEPLOYMENT                        │
│  ┌──────────────────────────────────────────────────────────────────────────────┐ │
│  │ Kubernetes 1.28+ · Helm (40+ templates) · ArgoCD GitOps · Docker Multi-stage │ │
│  │ StatefulSets: Kafka · TimescaleDB · ClickHouse · MinIO                       │ │
│  │ Deployments: Backend · Frontend · Celery · Flink · Stream Processor          │ │
│  │ ConfigMaps: Rules hot-reload · Notification webhooks · Backup schedules      │ │
│  └──────────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────────┘
```

## Data Flow

```
Agent/API → [TLS 1.3 + mTLS] → Ingest /batch → Kafka(events.raw)
    ↓
Stream Processor: Normalize → Dedup(Bloom) → Enrich(TI+Asset) → Window(5m/1hr)
    ↓                                    ↓
Kafka(events.normalized)          Kafka(alerts.triggered)
    ↓                                    ↓
Flink Jobs (5x SQL)              Alert Pipeline → DB dedup → Bloom dedup
    ↓                                    ↓
ClickHouse Analytics             Notifications (Slack/Teams/PD)
TimescaleDB Hypertables          Incident Creation
    ↓                                    ↓
Grafana Dashboards              SOC API → React SPA (WebSocket)
Prometheus Metrics              UEBA Score → Baseline Update
```

## Component Count

| Layer | Files | Lines (approx) |
|-------|-------|----------------|
| Tier 1: Gateway & Auth | 6 | 2,200 |
| Tier 2: Data Ingestion | 4 | 1,600 |
| Tier 3: Stream Processing | 4 | 2,000 |
| Tier 4: Analytics & Detection | 8 | 5,500 |
| Tier 5: Data Storage | 6 | 1,800 |
| Tier 6: Application Services | 22 | 15,000 |
| Tier 7: Frontend | 18 | 4,500 |
| Tier 8: Orchestration | 42 | 3,500 |
| Tier 9: Monitoring | 12 | 2,000 |
| **Total** | **122** | **~38,100** |
