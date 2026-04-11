import { TRPCError } from "@trpc/server";

export class AppError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly statusCode: number = 500,
    public readonly details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "AppError";
  }
}

export function toTRPCError(error: unknown): TRPCError {
  if (error instanceof TRPCError) {
    return error;
  }

  if (error instanceof AppError) {
    const codeMap: Record<number, TRPCError["code"]> = {
      400: "BAD_REQUEST",
      401: "UNAUTHORIZED",
      403: "FORBIDDEN",
      404: "NOT_FOUND",
      409: "CONFLICT",
      429: "TOO_MANY_REQUESTS",
    };

    return new TRPCError({
      code: codeMap[error.statusCode] ?? "INTERNAL_SERVER_ERROR",
      message: error.message,
      cause: error,
    });
  }

  const message =
    error instanceof Error ? error.message : "An unexpected error occurred";
  return new TRPCError({
    code: "INTERNAL_SERVER_ERROR",
    message,
    cause: error,
  });
}

export function notFound(resource: string): never {
  throw new TRPCError({
    code: "NOT_FOUND",
    message: `${resource} not found`,
  });
}

export function unauthorized(message = "Authentication required"): never {
  throw new TRPCError({
    code: "UNAUTHORIZED",
    message,
  });
}

export function forbidden(message = "Access denied"): never {
  throw new TRPCError({
    code: "FORBIDDEN",
    message,
  });
}

export function rateLimited(): never {
  throw new TRPCError({
    code: "TOO_MANY_REQUESTS",
    message: "Rate limit exceeded. Please try again later.",
  });
}
