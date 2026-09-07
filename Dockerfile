# Build stage: full toolchain, discarded afterwards.
FROM node:22-alpine AS build
WORKDIR /build

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build

# Reinstall without dev dependencies so only runtime packages are copied on.
RUN npm ci --omit=dev

FROM node:22-alpine AS runtime
WORKDIR /app

# node:alpine ships an unprivileged `node` user. The scanner needs no
# filesystem access beyond writing a report to a mounted directory, and no
# capabilities at all.
COPY --from=build --chown=node:node /build/node_modules ./node_modules
COPY --from=build --chown=node:node /build/dist ./dist
COPY --chown=node:node package.json README.md LICENSE ./

USER node

ENTRYPOINT ["node", "/app/dist/cli/index.js"]
CMD ["--help"]
