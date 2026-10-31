# The isoloir ingest (and authority, audit): the binary, bb to verify
# proofs, node for the ZKPassport verifier, git and ssh for the mirror.
FROM rust:1.90-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p isoloir

# bb: the Barretenberg version the circuits are built with (bb.js 5.0.0,
# the version browsers prove with). Its Linux binary links the GNU libc.
FROM node:22-bookworm-slim AS bb
WORKDIR /bb
RUN npm install --no-save --no-package-lock --ignore-scripts --no-audit --no-fund @aztec/bb.js@5.0.0 \
 && install -m 755 node_modules/@aztec/bb.js/build/amd64-linux/bb /usr/local/bin/bb \
 && /usr/local/bin/bb --version

FROM node:22-bookworm-slim AS zkverifier
WORKDIR /app/zkverifier
COPY zkverifier/package.json zkverifier/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
COPY zkverifier/verify.mjs ./

FROM node:22-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git openssh-client tzdata \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/isoloir /usr/local/bin/isoloir
COPY --from=bb /usr/local/bin/bb /usr/local/bin/bb
COPY --from=zkverifier /app/zkverifier /app/zkverifier
WORKDIR /app
ENV ISOLOIR_BB=/usr/local/bin/bb
# The mirror is cloned from ISOLOIR_MIRROR_GIT (pushed with
# ISOLOIR_MIRROR_SSH_KEY) at start when /app/mirror is empty; its circuits/
# come with it. PORT serves /v1/health, and the direct channel when the
# ledger lists one.
CMD ["isoloir", "ingest", "--mirror-dir", "/app/mirror", "--zkverifier", "/app/zkverifier/verify.mjs"]
