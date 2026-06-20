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

## Required Cloudflare Secrets (set once)

- SIGNER_SERVICE_TOKEN
- C2PA_SIGNER_PRIVATE_KEY_PEM
- C2PA_SIGNER_CERT_CHAIN_PEM