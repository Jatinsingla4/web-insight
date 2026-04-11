/**
 * RateLimiter Durable Object
 *
 * Provides precise per-user rate limiting using Durable Object storage.
 * More accurate than KV-based rate limiting for high-traffic scenarios.
 */
export class RateLimiter implements DurableObject {
  private readonly state: DurableObjectState;

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/check" && request.method === "POST") {
      const body = (await request.json()) as {
        key: string;
        maxRequests: number;
        windowMs: number;
      };

      const result = await this.check(
        body.key,
        body.maxRequests,
        body.windowMs,
      );

      return new Response(JSON.stringify(result), {
        headers: { "Content-Type": "application/json" },
      });
    }

    return new Response("Not Found", { status: 404 });
  }

  private async check(
    key: string,
    maxRequests: number,
    windowMs: number,
  ): Promise<{ allowed: boolean; remaining: number; resetAt: number }> {
    const now = Date.now();
    const storageKey = `rl:${key}`;

    const entry = await this.state.storage.get<{
      timestamps: number[];
    }>(storageKey);

    const timestamps = entry?.timestamps ?? [];
    const windowStart = now - windowMs;

    // Remove expired timestamps
    const active = timestamps.filter((t) => t > windowStart);

    if (active.length >= maxRequests) {
      return {
        allowed: false,
        remaining: 0,
        resetAt: active[0] + windowMs,
      };
    }

    active.push(now);
    await this.state.storage.put(storageKey, { timestamps: active });

    // Set alarm to clean up old entries
    const nextAlarm = await this.state.storage.getAlarm();
    if (!nextAlarm) {
      await this.state.storage.setAlarm(now + windowMs + 1000);
    }

    return {
      allowed: true,
      remaining: maxRequests - active.length,
      resetAt: active[0] + windowMs,
    };
  }

  async alarm(): Promise<void> {
    // Clean up expired rate limit entries
    const entries = await this.state.storage.list<{ timestamps: number[] }>({
      prefix: "rl:",
    });

    const now = Date.now();
    const toDelete: string[] = [];

    for (const [key, value] of entries) {
      const active = value.timestamps.filter(
        (t) => t > now - 60_000, // Keep last minute
      );
      if (active.length === 0) {
        toDelete.push(key);
      } else {
        await this.state.storage.put(key, { timestamps: active });
      }
    }

    if (toDelete.length > 0) {
      await this.state.storage.delete(toDelete);
    }
  }
}
