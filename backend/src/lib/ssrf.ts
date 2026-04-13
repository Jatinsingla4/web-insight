/**
 * SSRF protection — reject URLs that resolve to private/loopback/link-local
 * IP ranges or blocked hostnames before making any outbound fetch.
 */

const BLOCKED_HOST_RE =
  /^(localhost|.*\.local|.*\.internal|.*\.corp|.*\.example|.*\.test)$/i;

const BLOCKED_IP_PREFIXES = [
  /^10\./,                            // RFC 1918 private
  /^127\./,                           // loopback
  /^169\.254\./,                      // link-local / AWS metadata
  /^172\.(1[6-9]|2\d|3[01])\./,      // RFC 1918 private
  /^192\.168\./,                      // RFC 1918 private
  /^0\./,                             // "this" network
  /^100\.(6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\./, // RFC 6598 shared address
  /^::1$/,                            // IPv6 loopback
  /^fc[0-9a-f]{2}:/i,                 // IPv6 ULA
  /^fe80:/i,                          // IPv6 link-local
];

/**
 * Parse, validate, and return the URL.
 * Throws a plain Error with a user-safe message if the URL is not allowed.
 */
export function assertPublicUrl(urlStr: string): URL {
  let u: URL;
  try {
    u = new URL(urlStr);
  } catch {
    throw new Error("Invalid URL");
  }

  if (!/^https?:$/.test(u.protocol)) {
    throw new Error("Only http and https URLs are allowed");
  }

  const host = u.hostname.toLowerCase();

  if (BLOCKED_HOST_RE.test(host)) {
    throw new Error("Blocked hostname");
  }

  if (BLOCKED_IP_PREFIXES.some((re) => re.test(host))) {
    throw new Error("Blocked IP range");
  }

  return u;
}
