# Rust HTTP Signer - distroless runtime image
#
# This Dockerfile assumes the release binary was cross-compiled ahead of time
# by GitHub Actions for `x86_64-unknown-linux-gnu`.
#
# Build context: repo root
# Binary path:   target/x86_64-unknown-linux-gnu/release/artwork-c2pa-rust-http-signer
#
# Run locally for testing after you build the binary:
#   docker build -f signer-service/rust-http-signer/Dockerfile -t artwork-c2pa-rust-signer .
#   docker run --rm -p 8789:8789 -e RUST_SIGNER_HTTP_BIND=0.0.0.0:8789 artwork-c2pa-rust-signer

ARG SIGNER_GIT_SHA=unknown

FROM gcr.io/distroless/cc-debian12:nonroot

WORKDIR /app

COPY target/x86_64-unknown-linux-gnu/release/artwork-c2pa-rust-http-signer /app/artwork-c2pa-rust-http-signer

ENV RUST_SIGNER_HTTP_BIND=0.0.0.0:8789
ENV SIGNER_GIT_SHA=${SIGNER_GIT_SHA}
ENV C2PA_SIGNER_VERIFY_AFTER_READING=0
ENV C2PA_SIGNER_SELF_VERIFY_IGNORE_CERT_PROFILE=1

USER nonroot:nonroot
EXPOSE 8789

ENTRYPOINT ["/app/artwork-c2pa-rust-http-signer"]
