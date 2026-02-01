# ============================================================================
# LLMTrace Dashboard — Multi-stage Docker Build
# ============================================================================
# Produces a minimal Next.js standalone image.
#
# Build:  docker build -t llmtrace-dashboard ./dashboard
# Run:    docker run -p 3000:3000 -e LLMTRACE_API_URL=http://proxy:8080 llmtrace-dashboard
# ============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Install dependencies
# ---------------------------------------------------------------------------
FROM node:20-alpine AS deps
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --prefer-offline 2>/dev/null || npm install

# ---------------------------------------------------------------------------
# Stage 2: Build
# ---------------------------------------------------------------------------
FROM node:20-alpine AS builder
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY . .

ENV NEXT_TELEMETRY_DISABLED=1

RUN npm run build

# ---------------------------------------------------------------------------
# Stage 3: Production runtime
# ---------------------------------------------------------------------------
FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000

RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

COPY --from=builder /app/public ./public 2>/dev/null || true
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000

CMD ["node", "server.js"]
