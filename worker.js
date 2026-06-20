function buildCorsHeaders(request) {
  const origin = String(request?.headers?.get("Origin") || "").trim();
  const allowOrigin = origin || "*";
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type, X-Request-Id",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}

function jsonResponse(status, body, request = null) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...buildCorsHeaders(request)
    }
  });
}

function parseBearerToken(v) {
  const raw = String(v || "").trim();
  const m = raw.match(/^Bearer\s+(.+)$/i);
  return m ? String(m[1] || "").trim() : "";
}

function requireAuth(request, env) {
  const required = String(env.SIGNER_SERVICE_TOKEN || "").trim();
  if (!required) return;
  const presented = parseBearerToken(request.headers.get("Authorization"));
  if (!presented || presented !== required) {
    const err = new Error("Unauthorized");
    err.status = 401;
    throw err;
  }
}

function getContainerStub(env) {
  if (!env.RUST_SIGNER) return null;
  const id = env.RUST_SIGNER.idFromName("signing");
  return env.RUST_SIGNER.get(id);
}

export { RustSignerContainer, RustSignerContainerV2 } from "./rust-signer-container.js";

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);

      if (request.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: buildCorsHeaders(request) });
      }

      if (request.method === "GET" && url.pathname === "/health") {
        return jsonResponse(200, { success: true, mode: "rust-container" }, request);
      }

      if (request.method === "POST" && url.pathname === "/sign") {
        requireAuth(request, env);
        const stub = getContainerStub(env);
        if (!stub) {
          return jsonResponse(503, { success: false, message: "RUST_SIGNER binding not configured" }, request);
        }
        return await stub.fetch(request.clone());
      }

      return jsonResponse(404, { success: false, message: "Not found" }, request);
    } catch (err) {
      return jsonResponse(Number(err?.status || 400), {
        success: false,
        message: String(err?.message || err || "Request failed")
      }, request);
    }
  }
};