# FrostGate Forge Frontend
# Multi-stage build for optimized production image

# ============================================
# Stage 1: Dependencies
# ============================================
FROM node:20-alpine AS deps
RUN apk add --no-cache libc6-compat
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --only=production

# ============================================
# Stage 2: Builder
# ============================================
FROM node:20-alpine AS builder
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Build arguments for API URLs (can be overridden at build time)
ARG API_URL=http://spawn_service:8080
ARG ORCH_URL=http://orchestrator:8080
ARG SCORE_URL=http://scoreboard:8080

ENV API_URL=$API_URL
ENV ORCH_URL=$ORCH_URL
ENV SCORE_URL=$SCORE_URL
ENV NEXT_TELEMETRY_DISABLED=1

RUN npm run build

# ============================================
# Stage 3: Production Runner
# ============================================
FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

# Copy built application
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

CMD ["node", "server.js"]
