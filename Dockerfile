# The isoloir ingest (and trustee, audit): the binary, bb to verify
# proofs, node for the ZKPassport verifier, git and ssh for the mirror.
FROM rust:1.90-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p isoloir

FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends git openssh-client ca-certificates curl libc++1 && rm -rf /var/lib/apt/lists/*
# bb: the Barretenberg version the circuits were built with (5.0.0).
ARG BB_VERSION=5.0.0
RUN npm install -g @aztec/bb.js@${BB_VERSION} && ln -s "$(npm root -g)/@aztec/bb.js/build/amd64-linux/bb" /usr/local/bin/bb
COPY --from=build /src/target/release/isoloir /usr/local/bin/isoloir
COPY zkverifier /app/zkverifier
RUN cd /app/zkverifier && npm ci --omit=dev
# Known hosts for the git mirror's push over SSH.
RUN mkdir -p /root/.ssh && ssh-keyscan -t ed25519 github.com >> /root/.ssh/known_hosts 2>/dev/null
WORKDIR /app
ENV ISOLOIR_BB=/usr/local/bin/bb
ENTRYPOINT ["isoloir"]
# The mirror is cloned from ISOLOIR_MIRROR_GIT at start when /app/mirror is
# empty (an ephemeral disk); its circuits/ come with it. PORT serves the
# direct channel and /v1/health when the ledger lists one.
CMD ["ingest", "--mirror-dir", "/app/mirror", "--zkverifier", "/app/zkverifier/verify.mjs"]
