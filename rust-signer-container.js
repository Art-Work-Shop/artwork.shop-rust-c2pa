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
    constructor(ctx, env) {
        super(ctx, env);

        console.log("RustSignerContainerV2 env presence", {
            SIGNER_SERVICE_TOKEN: Boolean(env?.SIGNER_SERVICE_TOKEN),
            C2PA_SIGNER_PRIVATE_KEY_PEM: Boolean(env?.C2PA_SIGNER_PRIVATE_KEY_PEM),
            C2PA_SIGNER_CERT_CHAIN_PEM: Boolean(env?.C2PA_SIGNER_CERT_CHAIN_PEM),
            C2PA_SIGNER_SELF_TEST_IMAGE_URL: Boolean(env?.C2PA_SIGNER_SELF_TEST_IMAGE_URL),
        });

        this.envVars = {
            SIGNER_SERVICE_TOKEN: env.SIGNER_SERVICE_TOKEN,
            C2PA_SIGNER_PRIVATE_KEY_PEM: env.C2PA_SIGNER_PRIVATE_KEY_PEM,
            C2PA_SIGNER_CERT_CHAIN_PEM: env.C2PA_SIGNER_CERT_CHAIN_PEM,
            C2PA_SIGNER_SELF_TEST_IMAGE_URL: env.C2PA_SIGNER_SELF_TEST_IMAGE_URL,
        };
    }

    onStart() {
        console.log("RustSignerContainerV2 env lengths", {
            SIGNER_SERVICE_TOKEN: this.envVars?.SIGNER_SERVICE_TOKEN?.length || 0,
            C2PA_SIGNER_PRIVATE_KEY_PEM: this.envVars?.C2PA_SIGNER_PRIVATE_KEY_PEM?.length || 0,
            C2PA_SIGNER_CERT_CHAIN_PEM: this.envVars?.C2PA_SIGNER_CERT_CHAIN_PEM?.length || 0,
            C2PA_SIGNER_SELF_TEST_IMAGE_URL: this.envVars?.C2PA_SIGNER_SELF_TEST_IMAGE_URL?.length || 0,
        });
    }

    /**
     * Forward the incoming Worker fetch() call to the container process.
     * The Container base class handles port mapping and lifecycle automatically.
     */
    async fetch(request) {
        await this.startAndWaitForPorts();
        return this.containerFetch(request);
    }
}

// Keep legacy class name exported for historical migration compatibility.
export class RustSignerContainer extends RustSignerContainerV2 {}
