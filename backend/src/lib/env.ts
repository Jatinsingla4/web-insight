/// <reference types="@cloudflare/workers-types" />
export interface Env {
  // D1
  DB: D1Database;
  // R2
  R2: R2Bucket;
  // KV
  SESSIONS: KVNamespace;
  CACHE: KVNamespace;
  // Durable Objects
  SCAN_COORDINATOR: DurableObjectNamespace;
  RATE_LIMITER: DurableObjectNamespace;
  // Vectorize (future)
  // VECTORIZE: VectorizeIndex;
  // Secrets
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  SESSION_SECRET: string;
  RESEND_API_KEY?: string;
  // Vars
  ENVIRONMENT: string;
  FRONTEND_URL: string;
}

export interface AppContext {
  env: Env;
  userId?: string;
  waitUntil: (promise: Promise<unknown>) => void;
}
