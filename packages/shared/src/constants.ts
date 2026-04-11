export const SCAN_TIMEOUT_MS = 60_000;
export const MAX_BRANDS_PER_USER = 50;
export const MAX_SCANS_PER_HOUR = 20;
export const CACHE_TTL_SECONDS = 900; // 15 minutes
export const SESSION_DURATION_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
export const RATE_LIMIT_WINDOW_MS = 60_000; // 1 minute
export const RATE_LIMIT_MAX_REQUESTS = 60;

export const DNS_RECORD_TYPES = [
  "A",
  "AAAA",
  "CNAME",
  "MX",
  "NS",
  "TXT",
  "SOA",
  "SRV",
  "CAA",
] as const;
