# artwork.shop-rust-c2pa

Rust-only C2PA signer deployment for Cloudflare Containers.

## Layout

- rust-http-signer/               Rust signer service
- worker.js                       Cloudflare Worker router -> container DO
- rust-signer-container.js        Container class binding
- wrangler.toml                   Cloudflare container config
- .github/workflows/deploy.yml    Build + push + deploy pipeline

## Required GitHub Secrets

- CLOUDFLARE_API_TOKEN
- CLOUDFLARE_ACCOUNT_ID

These are CI/deploy credentials only. They let GitHub Actions push the image to GHCR and deploy the Worker config.

## Required Cloudflare Secrets (set once)

- SIGNER_SERVICE_TOKEN
- C2PA_SIGNER_PRIVATE_KEY_PEM
- C2PA_SIGNER_CERT_CHAIN_PEM

These are runtime signer secrets. They must exist in Cloudflare because the container needs them after deploy.

## Existing main PWA worker vars

If these already live in `artwork.shop-main`, keep them there. They are signer-orchestration inputs, not Rust container runtime secrets:

- C2PA_DRAIN_SECRET
- C2PA_DRAIN_WORKER_URL
- C2PA_LEGACY_EMBED_FALLBACK
- C2PA_PROVENANCE_PUBLISH_MODE
- C2PA_REQUIRED_CREDENTIAL_FORMAT
- C2PA_SIGNED_DERIVATIVE_FORMATS
- C2PA_SIGNER_APP_ASSERTIONS_INLINE_MAX_BYTES
- C2PA_SIGNER_KEY_ID
- C2PA_SIGNER_MANIFEST_TRANSPORT_PROFILE
- C2PA_SIGNER_MAX_REQUEST_BYTES
- C2PA_SIGNER_MODE
- C2PA_SIGNER_REQUESTED_EMBEDDING_MODE
- C2PA_SIGNER_SERVICE_URL
- C2PA_TSA_PROVIDERS_JSON

In other words: the main PWA worker decides policy and routing, and this repo only hosts the signer service behind that contract.

## What the Rust signer needs

The Rust container only needs the signer runtime values below:

- C2PA_SIGNER_SERVICE_TOKEN
- C2PA_SIGNER_PRIVATE_KEY_PEM
- C2PA_SIGNER_CERT_CHAIN_PEM
- C2PA_SIGNER_SELF_TEST_IMAGE_URL

Anything else should stay in the main worker unless the Rust signer code explicitly reads it.

The `C2PA_SIGNER_CREDENTIAL_FORMAT` value in `wrangler.toml` is a compatibility/config marker, not a required runtime secret.

## Fork setup

1. Fork this repo and open your fork in GitHub Actions.
2. Add the GitHub Secrets above in your fork's repository settings.
3. In Cloudflare, create or reuse a Worker that has Container support enabled.
4. Add the Cloudflare runtime secrets above to that Worker or via `wrangler secret put`.
5. Replace the placeholder image reference in `wrangler.toml` if you are deploying manually.
6. Run the `Build and Deploy Rust C2PA Signer` workflow.

## Secret split

- GitHub Actions: deploy auth and registry push access.
- Cloudflare runtime: signer credentials and request auth.
- Public config: worker name, container class, instance sizing, idle timeout, and non-secret vars.

## Expected image path

The GitHub Action builds `rust-http-signer` from the repo root and the Dockerfile copies the binary from:

`target/x86_64-unknown-linux-gnu/release/artwork-c2pa-rust-http-signer`

That keeps the build output aligned with the distroless container image.