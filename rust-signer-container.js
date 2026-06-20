/**
 * RustSignerContainer - Cloudflare Container binding for Rust HTTP Signer
 *
 * This class manages the lifecycle of the Rust HTTP signer container.
 * It extends Container (which extends DurableObject) and routes all
 * signing-related requests to the container process.
 *
 * The container binary is: artwork-c2pa-rust-http-signer
 * It listens on port 8789 inside the container.
 *
 * Container environment secrets are injected via the container configuration
 * in wrangler.toml - NOT passed through the Worker request.
 *
 * Usage from Worker:
 *   const id = env.RUST_SIGNER.idFromName("signing");
 *   const stub = env.RUST_SIGNER.get(id);
 *   const response = await stub.fetch(request);
 */
import { Container } from '@cloudflare/containers';

// Internal port where the Rust signer binary listens inside the container
const CONTAINER_PORT = 8789;

export class RustSignerContainerV2 extends Container {
    /**
     * The container's default port binding.
     * Requests forwarded via fetch() are routed to this port inside the container.
     */
    defaultPort = CONTAINER_PORT;

    /**
     * Forward the incoming Worker fetch() call to the container process.
     * The Container base class handles port mapping and lifecycle automatically.
     */
    async fetch(request) {
        return this.containerFetch(request);
    }
}

// Keep legacy class name exported for historical migration compatibility.
export class RustSignerContainer extends RustSignerContainerV2 {}
