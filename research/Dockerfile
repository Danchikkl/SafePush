# Synthetic-only research demo. No real credentials or provider access.
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci --ignore-scripts
COPY src ./src
RUN npm run build

FROM node:22-alpine
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY research/demo-agent-client.mjs ./research/demo-agent-client.mjs
USER node
