# syntax=docker/dockerfile:1

FROM oven/bun:1.2.21 AS build
WORKDIR /app

COPY package.json bun.lock* pnpm-lock.yaml* ./
COPY packages ./packages

RUN bun install --no-save
RUN cd packages/agents && bun run build
RUN cd packages/agents-control-plane && bun run build

FROM node:20-slim AS runtime
ENV NODE_ENV=production
ENV VERIDEX_CONTROL_PLANE_PORT=4010
ENV VERIDEX_CONTROL_PLANE_STORAGE_BACKEND=file
ENV VERIDEX_CONTROL_PLANE_DATA_DIR=/data
WORKDIR /app

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/packages/agents/dist ./packages/agents/dist
COPY --from=build /app/packages/agents/package.json ./packages/agents/package.json
COPY --from=build /app/packages/agents-control-plane/dist ./packages/agents-control-plane/dist
COPY --from=build /app/packages/agents-control-plane/package.json ./packages/agents-control-plane/package.json

RUN mkdir -p /data && chown -R node:node /app /data

USER node
EXPOSE 4010

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:4010/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "packages/agents-control-plane/dist/server-entry.mjs"]
