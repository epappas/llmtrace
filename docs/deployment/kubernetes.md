# Kubernetes Deployment Guide

Deploy LLMTrace on Kubernetes using the official Helm chart. The chart provisions:

- **LLMTrace Proxy** — the transparent LLM observability proxy (Deployment + Service + HPA)
- **ClickHouse** — analytical trace/span storage (Bitnami sub-chart)
- **PostgreSQL** — metadata storage for tenants, configs, audit events (Bitnami sub-chart)
- **Redis** — cache layer for hot queries, cost cap tracking, sessions (Bitnami sub-chart)

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Kubernetes cluster | ≥ 1.26 | Target platform |
| Helm | ≥ 3.12 | Chart installation |
| kubectl | ≥ 1.26 | Cluster access |
| Docker (optional) | ≥ 24 | Building the proxy image |

## Quick Start

### 1. Build the Proxy Image

```bash
# From the repository root
docker build -t llmtrace-proxy:0.1.0 .

# Push to your registry
docker tag llmtrace-proxy:0.1.0 your-registry.io/llmtrace-proxy:0.1.0
docker push your-registry.io/llmtrace-proxy:0.1.0
```

### 2. Update Helm Dependencies

```bash
cd deployments/helm/llmtrace
helm dependency update
```

This downloads the Bitnami sub-charts (ClickHouse, PostgreSQL, Redis) into the `charts/` directory.

### 3. Install (Development)

```bash
helm install llmtrace ./deployments/helm/llmtrace \
  --namespace llmtrace \
  --create-namespace \
  --set proxy.image.repository=your-registry.io/llmtrace-proxy
```

### 4. Install (Production)

```bash
helm install llmtrace ./deployments/helm/llmtrace \
  --namespace llmtrace \
  --create-namespace \
  -f ./deployments/helm/llmtrace/values-production.yaml \
  --set proxy.image.repository=your-registry.io/llmtrace-proxy \
  --set postgresql.auth.password=YOUR_SECURE_PASSWORD \
  --set secrets.postgresUrl="postgres://llmtrace:YOUR_SECURE_PASSWORD@llmtrace-postgresql:5432/llmtrace"
```

### 5. Verify

```bash
# Watch pods come up
kubectl get pods -n llmtrace -w

# Check proxy health
kubectl port-forward -n llmtrace svc/llmtrace 8080:80
curl http://localhost:8080/health
```

## Architecture Overview

```
                    ┌─────────────┐
     Internet ──────│   Ingress   │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │   Service   │  port 80 → 8080
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────▼────┐ ┌────▼─────┐ ┌────▼─────┐
        │  Proxy   │ │  Proxy   │ │  Proxy   │  ← HPA (2-20 replicas)
        │ Pod (1)  │ │ Pod (2)  │ │ Pod (N)  │
        └────┬─────┘ └────┬─────┘ └────┬─────┘
             │             │             │
     ┌───────┴─────────────┴─────────────┴───────┐
     │                                           │
┌────▼─────┐    ┌──────────┐    ┌────────┐
│ClickHouse│    │PostgreSQL│    │ Redis  │
│ (traces) │    │(metadata)│    │(cache) │
└──────────┘    └──────────┘    └────────┘
```

## Configuration Reference

### Proxy Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `proxy.replicaCount` | Number of proxy replicas | `1` |
| `proxy.image.repository` | Proxy container image | `llmtrace-proxy` |
| `proxy.image.tag` | Image tag (defaults to `appVersion`) | `""` |
| `proxy.upstreamUrl` | Upstream LLM provider URL | `https://api.openai.com` |
| `proxy.storageProfile` | Storage profile: `lite`, `memory`, `production` | `production` |
| `proxy.enableSecurityAnalysis` | Enable prompt injection detection | `true` |
| `proxy.enableTraceStorage` | Enable trace persistence | `true` |
| `proxy.enableStreaming` | Enable SSE streaming passthrough | `true` |
| `proxy.timeoutMs` | Request timeout (ms) | `30000` |
| `proxy.maxConnections` | Max concurrent connections | `1000` |
| `proxy.logging.level` | Log level | `info` |
| `proxy.logging.format` | Log format (`text` or `json`) | `json` |

### Service & Networking

| Parameter | Description | Default |
|-----------|-------------|---------|
| `service.type` | Kubernetes Service type | `ClusterIP` |
| `service.port` | Service port | `80` |
| `ingress.enabled` | Enable Ingress resource | `false` |
| `ingress.className` | Ingress class name | `""` |
| `ingress.hosts[0].host` | Ingress hostname | `llmtrace.local` |
| `ingress.tls` | TLS configuration | `[]` |

### Autoscaling

| Parameter | Description | Default |
|-----------|-------------|---------|
| `autoscaling.enabled` | Enable HPA | `false` |
| `autoscaling.minReplicas` | Minimum replicas | `2` |
| `autoscaling.maxReplicas` | Maximum replicas | `10` |
| `autoscaling.targetCPUUtilizationPercentage` | CPU target | `70` |
| `autoscaling.targetMemoryUtilizationPercentage` | Memory target | `80` |

### Secrets

| Parameter | Description | Default |
|-----------|-------------|---------|
| `secrets.create` | Create Secret from values | `true` |
| `secrets.existingSecret` | Use pre-existing Secret | `""` |
| `secrets.clickhouseUrl` | ClickHouse HTTP URL | `http://llmtrace-clickhouse:8123` |
| `secrets.clickhouseDatabase` | ClickHouse database name | `llmtrace` |
| `secrets.postgresUrl` | PostgreSQL connection URL | `postgres://llmtrace:llmtrace@...` |
| `secrets.redisUrl` | Redis connection URL | `redis://llmtrace-redis-master:6379` |

### Sub-charts

| Parameter | Description | Default |
|-----------|-------------|---------|
| `clickhouse.enabled` | Deploy bundled ClickHouse | `true` |
| `postgresql.enabled` | Deploy bundled PostgreSQL | `true` |
| `redis.enabled` | Deploy bundled Redis | `true` |

Set any sub-chart to `enabled: false` and configure `secrets.*Url` to point to your external service.

## Common Operations

### Upgrade

```bash
helm upgrade llmtrace ./deployments/helm/llmtrace \
  --namespace llmtrace \
  -f ./deployments/helm/llmtrace/values-production.yaml \
  --set proxy.image.tag=0.2.0
```

### Scale Manually

```bash
kubectl scale deployment llmtrace -n llmtrace --replicas=5
```

### View Logs

```bash
# All proxy pods
kubectl logs -n llmtrace -l app.kubernetes.io/name=llmtrace -f

# Single pod
kubectl logs -n llmtrace deployment/llmtrace -f
```

### Port-Forward for Local Access

```bash
# Proxy HTTP
kubectl port-forward -n llmtrace svc/llmtrace 8080:80

# Proxy gRPC (if enabled)
kubectl port-forward -n llmtrace svc/llmtrace 50051:50051

# ClickHouse (for debugging)
kubectl port-forward -n llmtrace svc/llmtrace-clickhouse 8123:8123

# PostgreSQL (for debugging)
kubectl port-forward -n llmtrace svc/llmtrace-postgresql 5432:5432
```

### Uninstall

```bash
helm uninstall llmtrace --namespace llmtrace

# Also delete PVCs (WARNING: destroys data)
kubectl delete pvc -n llmtrace --all
```

## Using External Services

To use externally managed databases instead of the bundled sub-charts:

```yaml
# values-external.yaml
clickhouse:
  enabled: false

postgresql:
  enabled: false

redis:
  enabled: false

secrets:
  create: true
  clickhouseUrl: "http://clickhouse.your-infra.svc:8123"
  clickhouseDatabase: "llmtrace"
  postgresUrl: "postgres://user:pass@postgres.your-infra.svc:5432/llmtrace"
  redisUrl: "redis://redis.your-infra.svc:6379"
```

```bash
helm install llmtrace ./deployments/helm/llmtrace \
  -f values-external.yaml \
  --namespace llmtrace --create-namespace
```

## Using an Existing Secret

If you manage secrets externally (e.g., via Sealed Secrets, External Secrets Operator, or Vault):

```yaml
secrets:
  create: false
  existingSecret: "my-llmtrace-credentials"
```

The existing Secret must contain these keys:

| Key | Description |
|-----|-------------|
| `LLMTRACE_CLICKHOUSE_URL` | ClickHouse HTTP endpoint |
| `LLMTRACE_CLICKHOUSE_DATABASE` | ClickHouse database name |
| `LLMTRACE_POSTGRES_URL` | PostgreSQL connection string |
| `LLMTRACE_REDIS_URL` | Redis connection string |

## Ingress with TLS (cert-manager)

The production values file includes a ready-to-use Ingress configuration for nginx + cert-manager:

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: llmtrace.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: llmtrace-tls
      hosts:
        - llmtrace.example.com
```

Ensure cert-manager is installed and a `ClusterIssuer` named `letsencrypt-prod` exists.

## Network Policies

Enable network policies to restrict traffic to the proxy:

```yaml
networkPolicy:
  enabled: true
```

This creates a NetworkPolicy that:
- Allows inbound HTTP (8080) and gRPC (50051) traffic
- Allows outbound to ClickHouse, PostgreSQL, Redis, DNS, and HTTPS (443)

## Monitoring

The proxy exposes a `/health` endpoint suitable for Kubernetes probes. For Prometheus integration, add pod annotations:

```yaml
proxy:
  podAnnotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "8080"
    prometheus.io/path: "/metrics"
```

## Troubleshooting

### Pods stuck in CrashLoopBackOff

Check logs and config:
```bash
kubectl logs -n llmtrace -l app.kubernetes.io/name=llmtrace --previous
kubectl describe configmap -n llmtrace llmtrace-config
```

### Cannot connect to ClickHouse/PostgreSQL/Redis

Verify the backing services are healthy:
```bash
kubectl get pods -n llmtrace
kubectl logs -n llmtrace -l app.kubernetes.io/name=clickhouse
kubectl logs -n llmtrace -l app.kubernetes.io/name=postgresql
kubectl logs -n llmtrace -l app.kubernetes.io/name=redis
```

Check the secret values match the actual service endpoints:
```bash
kubectl get secret -n llmtrace llmtrace -o jsonpath='{.data}' | \
  jq 'to_entries[] | {key: .key, value: (.value | @base64d)}'
```

### HPA not scaling

Ensure the metrics-server is installed:
```bash
kubectl get deployment -n kube-system metrics-server
kubectl top pods -n llmtrace
```
