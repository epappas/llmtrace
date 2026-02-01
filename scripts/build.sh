#!/usr/bin/env bash
# ============================================================================
# Build LLMTrace Docker image
# ============================================================================
# Usage:
#   ./scripts/build.sh              # build with default tag (latest)
#   ./scripts/build.sh v0.2.0       # build with specific tag
#   IMAGE=myregistry/llmtrace-proxy ./scripts/build.sh  # custom image name
# ============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Image name — defaults to ghcr.io/<github-owner>/llmtrace-proxy
IMAGE="${IMAGE:-ghcr.io/epappas/llmtrace-proxy}"

# Tag — first arg or "latest"
TAG="${1:-latest}"

# Also tag with git short SHA if available
GIT_SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo "unknown")"

echo "🔨 Building ${IMAGE}:${TAG} (sha: ${GIT_SHA})"

docker build \
  --tag "${IMAGE}:${TAG}" \
  --tag "${IMAGE}:${GIT_SHA}" \
  --label "org.opencontainers.image.source=https://github.com/epappas/llmtrace" \
  --label "org.opencontainers.image.revision=${GIT_SHA}" \
  --label "org.opencontainers.image.created=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  "$REPO_ROOT"

echo "✅ Built: ${IMAGE}:${TAG} and ${IMAGE}:${GIT_SHA}"
echo ""
echo "Run locally:"
echo "  docker run -p 8080:8080 --env-file .env ${IMAGE}:${TAG}"
