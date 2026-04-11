import { fetchRequestHandler } from "@trpc/server/adapters/fetch";
import { appRouter } from "./routers";
import { createContextFactory } from "./routers/context";
import { AuthService } from "./services/auth.service";
import type { Env } from "./lib/env";

// Re-export Durable Objects for wrangler
export { ScanCoordinator } from "./durable-objects/scan-coordinator";
export { RateLimiter } from "./durable-objects/rate-limiter";

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const corsHeaders = getCorsHeaders(env, request);

    // Handle CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    try {
      // ── Health check ────────────────────────────────────────────────────
      if (url.pathname === "/health") {
        return json({ status: "ok", timestamp: new Date().toISOString() }, corsHeaders);
      }

      // ── WebSocket upgrade for scan progress ─────────────────────────────
      if (url.pathname.startsWith("/ws/scan/")) {
        const brandId = url.pathname.split("/ws/scan/")[1];
        if (!brandId) {
          return json({ error: "Missing brandId" }, corsHeaders, 400);
        }

        const doId = env.SCAN_COORDINATOR.idFromName(brandId);
        const stub = env.SCAN_COORDINATOR.get(doId);

        // Forward the WebSocket request to the Durable Object
        return stub.fetch(request);
      }

      // ── OAuth redirect endpoint ─────────────────────────────────────────
      if (url.pathname === "/auth/google/callback") {
        return handleOAuthRedirect(request, env, corsHeaders);
      }

      // ── tRPC handler ───────────────────────────────────────────────────
      if (url.pathname.startsWith("/trpc")) {
        const response = await fetchRequestHandler({
          endpoint: "/trpc",
          req: request,
          router: appRouter,
          createContext: createContextFactory(env, ctx.waitUntil.bind(ctx)),
          onError({ error, path }) {
            if (error.code === "INTERNAL_SERVER_ERROR") {
              console.error(`[tRPC Error] ${path}:`, error.message);
            }
          },
        });

        // Apply CORS headers
        const newHeaders = new Headers(response.headers);
        for (const [key, value] of Object.entries(corsHeaders)) {
          newHeaders.set(key, value);
        }

        return new Response(response.body, {
          status: response.status,
          headers: newHeaders,
        });
      }

      return json({ error: "Not Found" }, corsHeaders, 404);
    } catch (error) {
      console.error("Unhandled error:", error);
      return json(
        { error: "Internal Server Error" },
        corsHeaders,
        500,
      );
    }
  },
} satisfies ExportedHandler<Env>;

/** Handle the browser OAuth redirect from Google. */
async function handleOAuthRedirect(
  request: Request,
  env: Env,
  corsHeaders: Record<string, string>,
): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");

  if (error) {
    return Response.redirect(
      `${env.FRONTEND_URL}/auth/callback?error=${encodeURIComponent(error)}`,
    );
  }

  if (!code || !state) {
    return json({ error: "Missing code or state" }, corsHeaders, 400);
  }

  try {
    const authService = new AuthService(env);
    const redirectUri = `${url.origin}/auth/google/callback`;
    const { sessionToken, user } = await authService.handleCallback(
      code,
      redirectUri,
    );

    // Redirect to frontend with session token
    const params = new URLSearchParams({
      token: sessionToken,
      userId: user.id,
      name: user.name,
    });

    return Response.redirect(
      `${env.FRONTEND_URL}/auth/callback?${params}`,
    );
  } catch (err) {
    console.error("OAuth callback error:", err);
    return Response.redirect(
      `${env.FRONTEND_URL}/auth/callback?error=auth_failed`,
    );
  }
}

function json(
  data: unknown,
  corsHeaders: Record<string, string>,
  status = 200,
): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders,
    },
  });
}

function getCorsHeaders(
  env: Env,
  request: Request,
): Record<string, string> {
  const origin = request.headers.get("Origin") ?? "";
  const allowedOrigins = [
    env.FRONTEND_URL,
    "http://localhost:3000",
    "http://localhost:5173",
  ];

  const isAllowed = allowedOrigins.includes(origin);

  return {
    "Access-Control-Allow-Origin": isAllowed ? origin : allowedOrigins[0],
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers":
      "Content-Type, Authorization, x-trpc-source",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Max-Age": "86400",
  };
}
