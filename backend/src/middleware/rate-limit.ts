import { RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_MS } from "@dns-checker/shared";
import type { Env } from "../lib/env";

interface RateLimitEntry {
  count: number;
  windowStart: number;
}

/**
 * Check rate limit for a given key (usually userId or IP).
 * Uses KV for distributed rate limiting across workers.
 */
export async function checkRateLimit(
  env: Env,
  key: string,
  maxRequests = RATE_LIMIT_MAX_REQUESTS,
  windowMs = RATE_LIMIT_WINDOW_MS,
): Promise<{ allowed: boolean; remaining: number; resetAt: number }> {
  const kvKey = `ratelimit:${key}`;
  const now = Date.now();

  const entry = await env.CACHE.get<RateLimitEntry>(kvKey, "json");

  if (!entry || now - entry.windowStart >= windowMs) {
    // New window
    const newEntry: RateLimitEntry = { count: 1, windowStart: now };
    await env.CACHE.put(kvKey, JSON.stringify(newEntry), {
      expirationTtl: Math.ceil(windowMs / 1000) + 1,
    });
    return {
      allowed: true,
      remaining: maxRequests - 1,
      resetAt: now + windowMs,
    };
  }

  if (entry.count >= maxRequests) {
    return {
      allowed: false,
      remaining: 0,
      resetAt: entry.windowStart + windowMs,
    };
  }

  entry.count++;
  await env.CACHE.put(kvKey, JSON.stringify(entry), {
    expirationTtl: Math.ceil(windowMs / 1000) + 1,
  });

  return {
    allowed: true,
    remaining: maxRequests - entry.count,
    resetAt: entry.windowStart + windowMs,
  };
}
