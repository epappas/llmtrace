#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <version>"
  echo "Example: $0 0.2.0"
  exit 1
fi

VERSION="$1"

# Validate semver format
if ! echo "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$'; then
  echo "ERROR: Invalid semver format: $VERSION"
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CARGO_TOML="$REPO_ROOT/Cargo.toml"

# Update workspace.package.version
sed -i "s/^\(version = \"\)[^\"]*\"/\1$VERSION\"/" "$CARGO_TOML"

# Update llmtrace-core workspace dependency version
sed -i "s/\(llmtrace-core = { path = \"crates\/llmtrace-core\", version = \"\)[^\"]*\"/\1$VERSION\"/" "$CARGO_TOML"

# Verify changes
echo "Updated $CARGO_TOML:"
grep -n 'version' "$CARGO_TOML" | head -5

# Sanity check: cargo resolves correctly
cd "$REPO_ROOT"
cargo check --workspace 2>/dev/null && echo "cargo check passed" || echo "WARNING: cargo check failed"

echo ""
echo "Next steps:"
echo "  git commit -m \"release: v$VERSION\""
echo "  git tag v$VERSION"
echo "  git push && git push --tags"
