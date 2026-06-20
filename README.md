# artwork.shop-rust-c2pa

Public Rust signer repo for the Cloudflare container deployment.

## What lives here

- `rust-http-signer/` Rust signer service
- `worker.js` Worker router to the signer container
- `rust-signer-container.js` Container binding
- `wrangler.toml` Container deployment config
- `.github/workflows/deploy.yml` Build and deploy pipeline

## Supported formats

The signer currently accepts these asset types:

- `image/jpeg`
- `image/webp`
- `image/svg+xml`
- `video/mp4`
- `audio/mpeg`

SVG is the preferred preview format for text-based look-inside samples. It works well for short readable excerpts because the preview can stay web-native while the purchased product remains a separately signed final asset.

## Public scope

This repo is public, but it is not the source of truth for the full C2PA topology. The main PWA worker in `artwork.shop-main` keeps policy, routing, TSA drain, and the broader orchestration vars.

Keep this repo limited to the signer service itself and its deployment wiring.

## Required GitHub Secrets

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`

These are CI and deploy credentials only. They let GitHub Actions push the image to GHCR and deploy the Worker config.

## Required Cloudflare runtime secrets

- `SIGNER_SERVICE_TOKEN`
- `C2PA_SIGNER_PRIVATE_KEY_PEM`
- `C2PA_SIGNER_CERT_CHAIN_PEM`

These belong in Cloudflare because the container needs them after deploy.

## Deployment flow

1. The workflow builds the Rust binary from `rust-http-signer/Cargo.toml`.
2. The Dockerfile packages that binary into a distroless container image.
3. GitHub Actions pushes the image to GHCR.
4. Wrangler deploys the Worker and pins the container image digest.

## Build output

The binary must land at:

`target/x86_64-unknown-linux-gnu/release/artwork-c2pa-rust-http-signer`

That path matches the Dockerfile copy step.