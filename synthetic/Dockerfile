# ── MCP SYNTHETIC — job image (#2724) ────────────────────────────────────────
#
# Runs synthetic/run.mjs as the Cloud Run job echelon-mcp-synthetic. Build context: mcp-server/
#   docker build -f mcp-server/synthetic/Dockerfile mcp-server
#
# What is in the image is the RUNNER, not the server under test: the runner installs the
# PUBLISHED echelongraph-mcp from npm on every run (MCP_SYNTHETIC_PACKAGE, default
# echelongraph-mcp@latest), into a fresh temporary directory, exactly as a user's `npx` does.
# Baking the package into the image would probe whatever was latest when the image was built.
# So the image needs npm at runtime, which the node image carries.
#
# The runner's own dependencies are this package's lockfile, production only: the MCP SDK's
# ajv validator (the one tools.test.mjs validates outputSchema with). test/mcp-stdio-client.mjs
# is the wire-level client the tests use, copied as is, so the synthetic speaks both eras the way
# the suite does.
FROM node:22-bookworm-slim

WORKDIR /synthetic
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
 && node -e 'import("@modelcontextprotocol/server/validators/ajv").then(() => console.log("ajv validator resolves"))'

COPY test/mcp-stdio-client.mjs test/mcp-stdio-client.mjs
COPY synthetic/run.mjs synthetic/probes.mjs synthetic/forwarder.mjs synthetic/

# Cloud Run's filesystem is in memory; npm's cache and the install go under /tmp (the runner
# points npm_config_cache into its temporary directory). Not root: the job needs no privilege.
ENV HOME=/tmp NODE_ENV=production
USER node
ENTRYPOINT ["node", "/synthetic/synthetic/run.mjs"]
