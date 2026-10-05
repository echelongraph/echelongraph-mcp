#!/usr/bin/env bash
# Builds echelongraph-mcp-<version>.mcpb: the MCP Bundle (Claude Desktop extension) that the public
# repo's release.yml builds from every release tag, checks with check-bundle.mjs on another runner
# before npm publishes, signs with a SLSA build-provenance attestation and attaches to the GitHub release as echelongraph-mcp.mcpb, the
# README's "Install in Claude Desktop" (#2815). It is also what Smithery's "Local (MCPB Bundle)"
# publish path takes for a stdio server (#2723).
#
#   mcp-server/listings/mcpb/build.sh [out-dir]     # default out-dir: mcp-server/listings/mcpb/out
#
# It builds dist/ from this checkout, stages dist/, package.json, LICENSE, README.md, this
# directory's manifest.json and icon.png, installs the production dependencies with
# `npm ci --omit=dev` from package-lock.json, then validates and packs with a pinned MCPB CLI.
# It publishes nothing: release.yml attaches the bundle it builds; a Smithery upload is a signed-in
# step (see ../README.md).
set -euo pipefail

MCPB_CLI="@anthropic-ai/mcpb@2.1.2"   # pinned; `npm view @anthropic-ai/mcpb version` on 2026-10-04
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG="$(cd "$HERE/../.." && pwd)"
OUT="${1:-$HERE/out}"

VERSION="$(node -p 'require(process.argv[1]).version' "$PKG/package.json")"
MANIFEST_VERSION="$(node -p 'require(process.argv[1]).version' "$HERE/manifest.json")"
if [ "$VERSION" != "$MANIFEST_VERSION" ]; then
  echo "REFUSED: manifest.json is at $MANIFEST_VERSION but package.json is at $VERSION; bump manifest.json first." >&2
  exit 1
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

(cd "$PKG" && npm run build >/dev/null)
cp -R "$PKG/dist" "$STAGE/dist"
cp "$PKG/package.json" "$PKG/package-lock.json" "$PKG/LICENSE" "$PKG/README.md" "$STAGE/"
cp "$HERE/manifest.json" "$HERE/icon.png" "$STAGE/"
(cd "$STAGE" && npm ci --omit=dev --ignore-scripts --no-audit --no-fund >/dev/null && rm package-lock.json)

mkdir -p "$OUT"
npx -y "$MCPB_CLI" validate "$STAGE/manifest.json"
npx -y "$MCPB_CLI" pack "$STAGE" "$OUT/echelongraph-mcp-$VERSION.mcpb"
echo "built $OUT/echelongraph-mcp-$VERSION.mcpb"
