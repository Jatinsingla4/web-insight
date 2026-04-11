import { initTRPC, TRPCError } from "@trpc/server";
import type { FetchCreateContextFnOptions } from "@trpc/server/adapters/fetch";
import type { Session } from "@dns-checker/shared";
import { validateRequest } from "../middleware/auth";
import { checkRateLimit } from "../middleware/rate-limit";
import { rateLimited } from "../lib/errors";
import type { Env } from "../lib/env";

export interface TrpcContext {
  env: Env;
  req: Request;
  session: Session | null;
  waitUntil: (promise: Promise<unknown>) => void;
}

export function createContextFactory(
  env: Env,
  waitUntil: (promise: Promise<unknown>) => void,
) {
  return async (opts: FetchCreateContextFnOptions): Promise<TrpcContext> => {
    const session = await validateRequest(opts.req, env);
    return {
      env,
      req: opts.req,
      session,
      waitUntil,
    };
  };
}

const t = initTRPC.context<TrpcContext>().create({
  errorFormatter({ shape, error }) {
    return {
      ...shape,
      data: {
        ...shape.data,
        code: error.code,
      },
    };
  },
});

export const router = t.router;
export const publicProcedure = t.procedure;
export const middleware = t.middleware;

/** Middleware: require authenticated session. */
const isAuthed = middleware(async ({ ctx, next }) => {
  if (!ctx.session) {
    throw new TRPCError({
      code: "UNAUTHORIZED",
      message: "You must be logged in to perform this action",
    });
  }
  return next({
    ctx: {
      ...ctx,
      session: ctx.session,
    },
  });
});

/** Middleware: enforce rate limiting. */
const isRateLimited = middleware(async ({ ctx, next }) => {
  const key = ctx.session?.userId ?? getClientIp(ctx.req);
  const result = await checkRateLimit(ctx.env, key);
  if (!result.allowed) {
    rateLimited();
  }
  return next();
});

export const protectedProcedure = publicProcedure.use(isAuthed).use(isRateLimited);
export const rateLimitedProcedure = publicProcedure.use(isRateLimited);

function getClientIp(req: Request): string {
  return (
    req.headers.get("cf-connecting-ip") ??
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    "unknown"
  );
}
