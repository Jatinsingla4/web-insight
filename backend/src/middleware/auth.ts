import { TRPCError } from "@trpc/server";
import type { Session } from "@dns-checker/shared";
import type { Env } from "../lib/env";

/** Extract session token from Authorization header or cookie. */
export function extractSessionToken(request: Request): string | null {
  // Check Authorization header first
  const authHeader = request.headers.get("Authorization");
  if (authHeader?.startsWith("Bearer ")) {
    return authHeader.slice(7);
  }

  // Check cookie
  const cookie = request.headers.get("Cookie");
  if (!cookie) return null;

  const match = cookie.match(/(?:^|;\s*)session=([^;]+)/);
  return match?.[1] ?? null;
}

/** Validate session and return user info. */
export async function validateRequest(
  request: Request,
  env: Env,
): Promise<Session | null> {
  const token = extractSessionToken(request);
  if (!token) return null;

  const session = await env.SESSIONS.get<Session>(
    `session:${token}`,
    "json",
  );

  if (!session || session.expiresAt < Date.now()) {
    if (session) {
      // Clean up expired session
      await env.SESSIONS.delete(`session:${token}`);
    }
    return null;
  }

  return session;
}

/** Assert that the request is authenticated. Throws UNAUTHORIZED if not. */
export async function requireAuth(
  request: Request,
  env: Env,
): Promise<Session> {
  const session = await validateRequest(request, env);
  if (!session) {
    throw new TRPCError({
      code: "UNAUTHORIZED",
      message: "Authentication required",
    });
  }
  return session;
}
