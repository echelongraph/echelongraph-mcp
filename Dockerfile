# echelongraph-mcp as a container: the same stdio server `npx -y echelongraph-mcp` runs, built
# from this directory's source (#2723, for the Docker MCP Catalog, docker/mcp-registry).
#
# This directory is published as the root of github.com/echelongraph/echelongraph-mcp, so the
# catalog entry (listings/docker/server.yaml) builds this file from that repo at a pinned commit.
#
#   docker build -t echelongraph-mcp .
#   docker run -i --rm echelongraph-mcp          # stdio: newline-delimited JSON-RPC on stdin/stdout
#
# Reproducible by construction:
#   * the base image is pinned by its multi-platform index digest, not by a moving tag;
#   * the only network use is `npm ci`, which installs exactly package-lock.json (integrity
#     hashes checked) and runs no install scripts;
#   * the runtime stage holds only dist/, the production node_modules and package.json (the
#     server reads its name and version from it for serverInfo and its User-Agent).
# The server sends no telemetry and makes no request other than the API call a tool needs to
# answer; it runs as the image's unprivileged `node` user (uid 1000).
#
# Base: node 22.23.3 on Alpine 3.24 (the node:22-alpine tag at 2026-10-03). To move it, resolve
# the new tag's index digest and change both parts together.
ARG NODE_IMAGE=node:22.23.3-alpine3.24@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402

# ── build: compile src/ to dist/ with the locked dev dependencies ──────────────
FROM ${NODE_IMAGE} AS build
WORKDIR /src
ENV npm_config_update_notifier=false npm_config_fund=false npm_config_audit=false
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# ── deps: the production dependencies only, from the same lockfile ────────────
FROM ${NODE_IMAGE} AS deps
WORKDIR /src
ENV npm_config_update_notifier=false npm_config_fund=false npm_config_audit=false
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

# ── runtime ───────────────────────────────────────────────────────────────────
FROM ${NODE_IMAGE}
ENV NODE_ENV=production
WORKDIR /app
COPY --from=deps /src/node_modules ./node_modules
COPY --from=build /src/dist ./dist
COPY package.json LICENSE ./
# The image's unprivileged `node` user, by number so a host can resolve it. Everything above is
# owned by root and not writable by that user, so the server cannot rewrite its own code.
USER 1000:1000
ENTRYPOINT ["node", "/app/dist/index.js"]
