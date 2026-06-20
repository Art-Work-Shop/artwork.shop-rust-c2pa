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