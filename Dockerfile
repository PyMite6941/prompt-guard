# Prompt Guard — local PII & prompt-injection scanner.
# Build: docker build -t prompt-guard .
# Run:   docker run --rm -v "$(pwd):/data" prompt-guard /data

FROM node:20-alpine AS build

WORKDIR /app
COPY package.json package-lock.json ./
COPY src ./src
COPY tsconfig.json ./
RUN npm ci

FROM node:20-alpine

WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY --from=build /app/dist ./dist
COPY examples/clean.txt examples/leak.txt ./examples/

ENTRYPOINT ["node", "dist/cli.js"]
CMD ["--help"]
