# Secrets Management

LLMTrace requires credentials for its backing services (ClickHouse, PostgreSQL, Redis). **Never commit real passwords to version control.** This guide covers the recommended approaches for managing secrets in production Kubernetes deployments.

## Overview

The Helm chart exposes two mechanisms for providing credentials:

| Mechanism | Values key | Description |
|-----------|-----------|-------------|
| **Chart-managed Secret** | `secrets.create: true` | The chart renders a `Secret` from values you supply via `--set` |
| **Pre-existing Secret** | `secrets.create: false` + `secrets.existingSecret` | You create the Secret yourself (or via an operator) |

Both approaches inject the following environment variables into the proxy pod:

| Variable | Example |
|----------|---------|
| `LLMTRACE_CLICKHOUSE_URL` | `http://llmtrace-clickhouse:8123` |
| `LLMTRACE_CLICKHOUSE_DATABASE` | `llmtrace` |
| `LLMTRACE_POSTGRES_URL` | `postgres://llmtrace:s3cret@llmtrace-postgresql:5432/llmtrace` |
| `LLMTRACE_REDIS_URL` | `redis://:s3cret@llmtrace-redis-master:6379` |

---

## Option 1: Inline `--set` (Simplest)

Pass secrets on the Helm install/upgrade command line. Good for CI/CD pipelines that pull secrets from a vault at deploy time.

```bash
helm install llmtrace ./deployments/helm/llmtrace \
  -f values-production.yaml \
  --namespace llmtrace --create-namespace \
  --set secrets.postgresUrl="postgres://llmtrace:$(vault read -field=pg_password secret/llmtrace)@llmtrace-postgresql:5432/llmtrace" \
  --set secrets.redisUrl="redis://:$(vault read -field=redis_password secret/llmtrace)@llmtrace-redis-master:6379" \
  --set postgresql.auth.password="$(vault read -field=pg_password secret/llmtrace)" \
  --set redis.auth.password="$(vault read -field=redis_password secret/llmtrace)" \
  --set clickhouse.auth.password="$(vault read -field=ch_password secret/llmtrace)"
```

> **Tip:** Wrap this in a shell script or CI step so secrets never appear in checked-in files.

---

## Option 2: External Secrets Operator (Recommended for Production)

The [External Secrets Operator](https://external-secrets.io/) syncs secrets from cloud vaults (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault, etc.) into Kubernetes `Secret` objects automatically.

### Prerequisites

```bash
# Install the operator
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets \
  --namespace external-secrets --create-namespace
```

### 1. Create a `SecretStore` (or `ClusterSecretStore`)

```yaml
# secret-store.yaml
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: aws-secrets-manager
  namespace: llmtrace
spec:
  provider:
    aws:
      service: SecretsManager
      region: eu-west-1
      auth:
        secretRef:
          accessKeyIDSecretRef:
            name: aws-credentials
            key: access-key-id
          secretAccessKeySecretRef:
            name: aws-credentials
            key: secret-access-key
```

### 2. Create an `ExternalSecret`

```yaml
# external-secret.yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: llmtrace
  namespace: llmtrace
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: llmtrace          # Must match secrets.existingSecret
    creationPolicy: Owner
  data:
    - secretKey: LLMTRACE_POSTGRES_URL
      remoteRef:
        key: llmtrace/production
        property: postgres_url
    - secretKey: LLMTRACE_REDIS_URL
      remoteRef:
        key: llmtrace/production
        property: redis_url
    - secretKey: LLMTRACE_CLICKHOUSE_URL
      remoteRef:
        key: llmtrace/production
        property: clickhouse_url
    - secretKey: LLMTRACE_CLICKHOUSE_DATABASE
      remoteRef:
        key: llmtrace/production
        property: clickhouse_database
```

```bash
kubectl apply -f secret-store.yaml
kubectl apply -f external-secret.yaml
```

### 3. Install LLMTrace referencing the external secret

```bash
helm install llmtrace ./deployments/helm/llmtrace \
  -f values-production.yaml \
  --namespace llmtrace \
  --set secrets.create=false \
  --set secrets.existingSecret=llmtrace
```

---

## Option 3: Sealed Secrets

[Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets) lets you encrypt secrets with a cluster-specific key so the encrypted form can be safely committed to Git.

### Prerequisites

```bash
# Install the controller
helm repo add sealed-secrets https://bitnami-labs.github.io/sealed-secrets
helm install sealed-secrets sealed-secrets/sealed-secrets \
  --namespace kube-system

# Install the CLI
brew install kubeseal   # or download from GitHub releases
```

### 1. Create a regular Secret manifest (do NOT apply it)

```bash
kubectl create secret generic llmtrace \
  --namespace llmtrace \
  --from-literal=LLMTRACE_POSTGRES_URL='postgres://llmtrace:s3cret@llmtrace-postgresql:5432/llmtrace' \
  --from-literal=LLMTRACE_REDIS_URL='redis://:r3dis@llmtrace-redis-master:6379' \
  --from-literal=LLMTRACE_CLICKHOUSE_URL='http://llmtrace-clickhouse:8123' \
  --from-literal=LLMTRACE_CLICKHOUSE_DATABASE='llmtrace' \
  --dry-run=client -o yaml > /tmp/llmtrace-secret.yaml
```

### 2. Seal it

```bash
kubeseal --format yaml < /tmp/llmtrace-secret.yaml > sealed-secret.yaml
rm /tmp/llmtrace-secret.yaml   # delete the plaintext!
```

### 3. Apply and install

```bash
kubectl apply -f sealed-secret.yaml

helm install llmtrace ./deployments/helm/llmtrace \
  -f values-production.yaml \
  --namespace llmtrace \
  --set secrets.create=false \
  --set secrets.existingSecret=llmtrace
```

The sealed secret YAML is safe to commit to Git — only the cluster's controller can decrypt it.

---

## Option 4: Manual Kubernetes Secret

Create the secret directly with `kubectl` before installing the Helm chart.

```bash
kubectl create namespace llmtrace

kubectl create secret generic llmtrace-manual \
  --namespace llmtrace \
  --from-literal=LLMTRACE_POSTGRES_URL='postgres://llmtrace:s3cret@llmtrace-postgresql:5432/llmtrace' \
  --from-literal=LLMTRACE_REDIS_URL='redis://:r3dis@llmtrace-redis-master:6379' \
  --from-literal=LLMTRACE_CLICKHOUSE_URL='http://llmtrace-clickhouse:8123' \
  --from-literal=LLMTRACE_CLICKHOUSE_DATABASE='llmtrace'

helm install llmtrace ./deployments/helm/llmtrace \
  -f values-production.yaml \
  --namespace llmtrace \
  --set secrets.create=false \
  --set secrets.existingSecret=llmtrace-manual
```

---

## Using `existingSecret` in the Helm Chart

The chart's `_helpers.tpl` selects the secret name with:

```yaml
{{- define "llmtrace.secretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- include "llmtrace.fullname" . }}
{{- end }}
{{- end }}
```

The deployment template uses `envFrom.secretRef` to inject **all** keys from the chosen secret as environment variables:

```yaml
envFrom:
  - secretRef:
      name: {{ include "llmtrace.secretName" . }}
```

Your external secret must contain at minimum:
- `LLMTRACE_CLICKHOUSE_URL`
- `LLMTRACE_CLICKHOUSE_DATABASE`
- `LLMTRACE_POSTGRES_URL`
- `LLMTRACE_REDIS_URL`

---

## Sub-chart Credentials

The ClickHouse, PostgreSQL, and Redis Bitnami sub-charts manage their own secrets independently. When using external secrets, you'll typically either:

1. **Disable the sub-charts** (`clickhouse.enabled: false`, etc.) and point to externally managed databases, or
2. **Pass sub-chart passwords** via `--set` so the sub-charts create their own secrets:

```bash
helm install llmtrace ./deployments/helm/llmtrace \
  -f values-production.yaml \
  --set secrets.create=false \
  --set secrets.existingSecret=llmtrace-external \
  --set postgresql.auth.password="$PG_PASSWORD" \
  --set redis.auth.password="$REDIS_PASSWORD" \
  --set clickhouse.auth.password="$CH_PASSWORD"
```

---

## Security Checklist

- [ ] No plaintext passwords in any committed `values*.yaml` files
- [ ] Production `secrets.postgresUrl` and `secrets.redisUrl` are set via `--set` or external secret
- [ ] `redis.auth.enabled: true` in production
- [ ] ClickHouse, PostgreSQL, and Redis passwords are non-empty in production
- [ ] Secret rotation plan documented and tested
- [ ] RBAC limits who can `kubectl get secret` in the namespace
