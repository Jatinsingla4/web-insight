import { createTRPCReact } from "@trpc/react-query";
import { httpBatchLink } from "@trpc/client";
import type { AppRouter } from "@dns-checker/api/src/routers";

export const trpc = createTRPCReact<AppRouter>();

export function getBaseUrl(): string {
  if (typeof window !== "undefined") {
    return process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8787";
  }
  return process.env.API_URL ?? "http://localhost:8787";
}

export function getAppUrl(): string {
  if (typeof window !== "undefined") {
    return window.location.origin;
  }
  return process.env.NEXT_PUBLIC_APP_URL ?? "http://localhost:3000";
}

export function createTrpcClient(sessionToken: string | null) {
  return trpc.createClient({
    links: [
      httpBatchLink({
        url: `${getBaseUrl()}/trpc`,
        headers() {
          const headers: Record<string, string> = {
            "x-trpc-source": "web",
          };
          if (sessionToken) {
            headers["Authorization"] = `Bearer ${sessionToken}`;
          }
          return headers;
        },
        fetch(url, options) {
          return fetch(url, {
            ...options,
            credentials: "include",
          });
        },
      }),
    ],
  });
}
