#!/usr/bin/env bash
# ============================================================================
# Push LLMTrace Docker image to GitHub Container Registry
# ============================================================================
# Prerequisites:
#   echo $GITHUB_TOKEN | docker login ghcr.io -u <username> --password-stdin
#
# Usage:
#   ./scripts/push.sh               # push :latest + :sha
#   ./scripts/push.sh v0.2.0        # push specific tag + :sha
#   IMAGE=myregistry/llmtrace-proxy ./scripts/push.sh  # custom registry
# ============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

IMAGE="${IMAGE:-ghcr.io/epappas/llmtrace-proxy}"
TAG="${1:-latest}"
GIT_SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo "unknown")"

# Ensure images exist locally
if ! docker image inspect "${IMAGE}:${TAG}" &>/dev/null; then
  echo "❌ Image ${IMAGE}:${TAG} not found locally. Run scripts/build.sh first."
  exit 1
fi

echo "🚀 Pushing ${IMAGE}:${TAG}"
docker push "${IMAGE}:${TAG}"

if docker image inspect "${IMAGE}:${GIT_SHA}" &>/dev/null; then
  echo "🚀 Pushing ${IMAGE}:${GIT_SHA}"
  docker push "${IMAGE}:${GIT_SHA}"
fi

echo ""
echo "✅ Pushed successfully."
echo "   ${IMAGE}:${TAG}"
echo "   ${IMAGE}:${GIT_SHA}"
echo ""
echo "Pull with:"
echo "  docker pull ${IMAGE}:${TAG}"
