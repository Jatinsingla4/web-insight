import type { z } from "zod";
import type {
  techStackItemSchema,
  dnsRecordSchema,
  sslCertificateSchema,
  scanResultSchema,
} from "./schemas";

// ── Inferred types from schemas ─────────────────────────────────────────────
export type TechStackItem = z.infer<typeof techStackItemSchema>;
export type DnsRecord = z.infer<typeof dnsRecordSchema>;
export type SslCertificate = z.infer<typeof sslCertificateSchema>;
export type ScanResult = z.infer<typeof scanResultSchema>;

// ── Database models ─────────────────────────────────────────────────────────
export interface User {
  id: string;
  email: string;
  name: string;
  avatarUrl: string | null;
  googleId: string;
  createdAt: string;
  updatedAt: string;
}

export interface Brand {
  id: string;
  userId: string;
  domain: string;
  name: string;
  lastScanId: string | null;
  lastScannedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface Scan {
  id: string;
  brandId: string;
  status: ScanStatus;
  tech_stack_json: string | null;
  dns_json: string | null;
  ssl_json: string | null;
  extra_data_json: string | null;
  raw_response_r2_key: string | null;
  error_message: string | null;
  started_at: string;
  completed_at: string | null;
  created_at: string;
}

export type ScanStatus = "pending" | "running" | "completed" | "failed";

// ── WebSocket messages ──────────────────────────────────────────────────────
export type WsMessageType =
  | "scan:started"
  | "scan:progress"
  | "scan:completed"
  | "scan:failed"
  | "error";

export interface WsMessage {
  type: WsMessageType;
  scanId: string;
  data?: Record<string, unknown>;
  progress?: number;
  message?: string;
}

// ── API response wrappers ───────────────────────────────────────────────────
export interface ApiError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

// ── Session ─────────────────────────────────────────────────────────────────
export interface Session {
  userId: string;
  email: string;
  name: string;
  avatarUrl: string | null;
  expiresAt: number;
}
