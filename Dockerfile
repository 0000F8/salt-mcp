# salt-mcp public (stdio) image: ghcr.io/0000f8/salt-mcp
#
# Build with THIS repo as the context, plus the sibling salt-agent-sdk repo
# supplied as an ADDITIONAL named build context called "sdksrc" (buildx
# --build-context, https://docs.docker.com/build/building/context/#additional-build-contexts).
# That keeps this Dockerfile's own context (and this file's .dockerignore)
# scoped to salt-mcp, instead of requiring a shared parent directory the way
# salt-deploy/docker/mcp.Dockerfile does for the hosted image.
#
#   docker buildx build \
#     --build-context sdksrc=../salt-agent-sdk \
#     -t salt-mcp:local .
#
# Why the SDK is built from source at all: salt-mcp depends on
# "salt-agent-sdk": "^0.9.0", but the package published to the public npm
# registry is still 0.1.0 -- `npm ci` against the checked-in lockfile fails
# ("Invalid: lock file's salt-agent-sdk@0.1.0 does not satisfy
# salt-agent-sdk@^0.9.0") because there is no npm release new enough. The dev
# checkout works around this with an npm workspace symlink into a sibling
# checkout of https://github.com/0000F8/salt-agent-sdk, which a standalone
# CI/build environment doesn't have -- so this image reconstructs the same
# sibling relationship explicitly, at a version pinned by sdk.ref, and packs
# it into a tarball instead of relying on a symlink.
#
# The SDK's `prepare` script is `npm run build` (tsc), which npm re-runs on
# every install/prune -- pruning it in place in the final image would then
# immediately fail rebuilding with the compiler gone. Building it in an
# isolated stage sidesteps that: nothing here is pruned, and only the packed
# tarball crosses into the runtime image.

# ---------------------------------------------------------------------------
# Stage 1: build salt-agent-sdk (from the "sdksrc" additional context) and
# pack it into a tarball.
# ---------------------------------------------------------------------------
# --platform=$BUILDPLATFORM: tsc and npm pack are architecture-neutral, and
# running them under QEMU for the arm64 half of a multi-arch build crashed
# node with SIGILL (exit 132) on the v0.2.2 release build. Build once,
# natively; the tarball is the same for every target.
FROM --platform=$BUILDPLATFORM node:22-alpine AS sdk-builder

WORKDIR /salt-agent-sdk
COPY --from=sdksrc . .
RUN npm ci --include=dev && npm pack --pack-destination /tmp

# ---------------------------------------------------------------------------
# Stage 2: install salt-mcp's dependencies, natively for the same reason as
# above. The lockfile carries no platform-specific or native package
# (checked: no cpu/os/hasInstallScript entries), so node_modules built on
# the build platform is byte-identical to what the target would produce.
# ---------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM node:22-alpine AS deps

WORKDIR /app
ENV NODE_ENV=production
COPY --from=sdk-builder /tmp/salt-agent-sdk-*.tgz /tmp/
COPY package.json package-lock.json ./
RUN node -e "\
const fs = require('fs'); \
const dep = 'salt-agent-sdk'; \
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8')); \
if (!pkg.dependencies || !pkg.dependencies[dep]) { \
  throw new Error(dep + ' is no longer a dependency of salt-mcp -- this image still bundles it from source; drop that step or restore the dependency'); \
} \
delete pkg.dependencies[dep]; \
fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2) + '\n'); \
const lock = JSON.parse(fs.readFileSync('package-lock.json', 'utf8')); \
for (const key of Object.keys(lock.packages || {})) { \
  if (key === 'node_modules/' + dep || key.startsWith('node_modules/' + dep + '/')) delete lock.packages[key]; \
} \
if (lock.packages && lock.packages['']) delete lock.packages[''].dependencies[dep]; \
for (const key of Object.keys(lock.dependencies || {})) { if (key === dep) delete lock.dependencies[key]; } \
fs.writeFileSync('package-lock.json', JSON.stringify(lock, null, 2) + '\n'); \
" \
 && npm ci --omit=dev \
 && npm install --omit=dev --no-save /tmp/salt-agent-sdk-*.tgz \
 && rm -f /tmp/salt-agent-sdk-*.tgz \
 && npm cache clean --force \
 && rm -rf /root/.npm

# ---------------------------------------------------------------------------
# Stage 3: runtime image (the real target platform; nothing is compiled here).
# ---------------------------------------------------------------------------
FROM node:22-alpine

# io.modelcontextprotocol.server.name is how the MCP Registry verifies that an OCI
# package listed under ai.saltapp/salt is really ours (it reads the image's labels).
LABEL org.opencontainers.image.source="https://github.com/0000F8/salt-mcp" \
      org.opencontainers.image.description="Salt MCP server (stdio) -- chat, pay, and hire on Salt (saltapp.ai) as one of its AI agents." \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.url="https://saltapp.ai" \
      org.opencontainers.image.vendor="0x0000F8" \
      io.modelcontextprotocol.server.name="ai.saltapp/salt"

WORKDIR /app
ENV NODE_ENV=production
COPY --from=deps /app/node_modules ./node_modules

# Trim salt-agent-sdk from package.json/package-lock.json as ONE consistent
# edit (so `npm ci` still pins every other dependency exactly against the
# real lockfile), install the rest from the lock, then install the
# from-source SDK tarball on top. See salt-deploy/docker/mcp.Dockerfile for
# the same pattern applied to the hosted HTTP image.

# Restore salt-mcp's real, untrimmed package.json/lock over the temporary
# copies above -- node_modules already has the right contents, and the
# shipped image should carry the manifest the repo actually has.
COPY . .

# Never root: node:22-alpine's built-in `node` user (uid 1000) owns the app.
RUN chown -R node:node /app
USER node

ENTRYPOINT ["node", "src/index.mjs"]
