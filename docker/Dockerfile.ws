FROM oven/bun:1

WORKDIR /usr/src/app

COPY ../packages/ ./packages
COPY ../bun.lock ./bun.lock
COPY ../package.json ./package.json
COPY ../turbo.json ./turbo.json
COPY ../apps/ws/ ./apps/ws

RUN bun install
RUN bun run db:generate

EXPOSE 8081

CMD bun run db:migrate && bun run start:ws
