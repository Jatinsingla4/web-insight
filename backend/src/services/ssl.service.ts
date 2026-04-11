import type { SslCertificate } from "@dns-checker/shared";
import { CACHE_TTL_SECONDS } from "@dns-checker/shared";
import type { DnsService } from "./dns.service";

interface CertSpotterEntry {
  id: string;
  dns_names: string[];
  issuer: {
    name: string;
    friendly_name?: string;
  };
  not_before: string;
  not_after: string;
  cert_sha256: string;
}

// SSL Labs v3 API response types (only fields we use)
interface SslLabsProtocol {
  id: number;
  name: string;   // "TLS"
  version: string; // "1.3", "1.2"
}

interface SslLabsEndpointDetails {
  protocols?: SslLabsProtocol[];
  key?: { size: number; alg: string };
  cert?: { 
    sigAlg: string;
    issuerSubject: string;
    notBefore: number;
    notAfter: number;
    altNames: string[];
  };
  alpnProtocols?: string[];
  ocspStapling?: boolean;
  forwardSecrecy?: number; // 0=No, 1=ECDHE only, 2=DH+ECDHE, 4=robust
  heartbleed?: boolean;
  poodle?: boolean;
  poodleTls?: number;
  vulnBeast?: boolean;
  freak?: boolean;
  logjam?: boolean;
  drownVulnerable?: boolean;
}

interface SslLabsEndpoint {
  grade?: string;
  details?: SslLabsEndpointDetails;
}

interface SslLabsResponse {
  status: string; // "DNS", "IN_PROGRESS", "READY", "ERROR"
  startTime?: number;
  testTime?: number;
  endpoints?: SslLabsEndpoint[];
}

const BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36";
const SSL_CACHE_PREFIX = "ssl:sentinel:v3";

interface ScanPersistenceInfo {
  r2Key: string;
  scanId: string;
}

export class SslService {
  private r2?: R2Bucket;
  private db?: D1Database;

  constructor(
    private readonly cache: KVNamespace,
    private readonly dns: DnsService,
  ) {}

  /** Call after brandScan stores results so deep scan can update R2/D1 */
  registerPersistence(domain: string, r2Key: string, scanId: string, r2: R2Bucket, db: D1Database): void {
    this.r2 = r2;
    this.db = db;
    // Store persistence info in KV so background poll can find it
    this.cache.put(`ssl:persist:${domain}`, JSON.stringify({ r2Key, scanId }), {
      expirationTtl: 600, // 10 min — enough for deep scan to complete
    });
  }

  async analyze(
    domain: string,
    force = false,
    ctx?: { waitUntil: (p: Promise<any>) => void },
  ): Promise<SslCertificate | null> {
    const cacheKey = `${SSL_CACHE_PREFIX}:${domain}`;

    if (!force) {
      const cached = await this.cache.get<SslCertificate>(cacheKey, "json");
      if (cached) {
        // Return ready results immediately
        if (cached.deepScanStatus === "ready") return cached;

        // If scanning, check if it's stale (more than 5 mins old)
        const scannedAtTime = cached.scannedAt ? new Date(cached.scannedAt).getTime() : 0;
        const isStaleScanning = cached.deepScanStatus === "scanning" &&
          (Date.now() - scannedAtTime > 5 * 60 * 1000);

        if (cached.deepScanStatus === "scanning" && !isStaleScanning) {
          // Re-trigger background poll in case previous Worker died
          if (ctx?.waitUntil) {
            ctx.waitUntil(this.pollSslLabs(domain, false));
          }
          return cached;
        }

        // Stale or failed — continue to re-trigger a fresh scan
      }
    }

    // Phase 1: All fast sources in parallel — cert lookup, DNS checks, HTTPS probe, SSL Labs cache
    const [cert, caaPresent, probe, fastCacheMetrics] = await Promise.all([
      this.fetchCertWithFallbacks(domain),
      this.dns.checkCaa(domain).catch(() => false),
      this.probeHttps(domain).catch(() => null),
      this.fetchSslLabsFastCache(domain, Date.now()).catch(() => null)
    ]);

    // Build result from cert + probe data (TLS version from Alt-Svc header)
    const result = this.buildResult(domain, cert, probe);
    result.caaRecordPresent = caaPresent;

    // Overlay SSL Labs cached metrics if available (grade, protocol, vulns, etc.)
    if (fastCacheMetrics) {
      for (const [key, value] of Object.entries(fastCacheMetrics)) {
        if (value !== null && value !== undefined) {
          (result as any)[key] = value;
        }
      }
    }

    result.deepScanStatus = fastCacheMetrics?.deepScanStatus === "ready" ? "ready" : "scanning";
    result.scannedAt = new Date().toISOString();

    // Cache the fast result immediately so UI has data
    await this.cache.put(cacheKey, JSON.stringify(result), {
      expirationTtl: CACHE_TTL_SECONDS,
    });

    // Phase 2: Background Deep Audit
    if (ctx?.waitUntil) {
      ctx.waitUntil(this.pollSslLabs(domain, true));
    }

    return result;
  }

  /**
   * Poll SSL Labs until scan completes or max retries reached.
   * startNew=true on first call, then poll without it.
   */
  private async pollSslLabs(domain: string, startNew: boolean): Promise<void> {
    const cacheKey = `${SSL_CACHE_PREFIX}:${domain}`;
    const maxRetries = 15; // up to ~5 mins total (10s + 14×20s = 290s)

    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        const isFirstAttempt = attempt === 0;
        const params = new URLSearchParams({
          host: domain,
          publish: "off",
          ignoreMismatch: "on",
          all: "done",
        });
        // Only pass startNew=on on the very first request
        if (startNew && isFirstAttempt) params.set("startNew", "on");

        const url = `https://api.ssllabs.com/api/v3/analyze?${params}`;
        const response = await fetch(url, {
          headers: { "User-Agent": BROWSER_UA },
          signal: AbortSignal.timeout(8000), // Reduced from 15s
        });

        // Rate limited — wait 30s before retry
        if (response.status === 429) {
          await this.sleep(30000);
          continue;
        }

        if (!response.ok) {
          await this.markDeepScanFailed(cacheKey);
          return;
        }

        const data = (await response.json()) as SslLabsResponse;

        if (data.status === "READY" && data.endpoints?.[0]) {
          await this.mergeDeepScanResults(cacheKey, data.endpoints[0]);
          return;
        }

        if (data.status === "ERROR") {
          await this.markDeepScanFailed(cacheKey);
          return;
        }

        // DNS or IN_PROGRESS — keep polling
        // 10s wait on first attempt, 20s thereafter
        await this.sleep(isFirstAttempt ? 10000 : 20000);
      } catch {
        // Network error or timeout — keep trying unless last attempt
        if (attempt === maxRetries - 1) {
          await this.markDeepScanFailed(cacheKey);
        }
        await this.sleep(20000);
      }
    }

    // Exhausted retries without READY — mark failed so next scan retries
    await this.markDeepScanFailed(cacheKey);
  }

  private async mergeDeepScanResults(
    cacheKey: string,
    endpoint: SslLabsEndpoint,
  ): Promise<void> {
    const existing = await this.cache.get<SslCertificate>(cacheKey, "json");
    if (!existing) return;

    const details = endpoint.details;

    // Build TLS protocol string correctly: "TLS 1.3", "TLS 1.2"
    const latestProtocol = details?.protocols?.[0];
    const protocolStr = latestProtocol
      ? `${latestProtocol.name} ${latestProtocol.version}`
      : existing.protocol;

    const issuer = details?.cert?.issuerSubject 
      ? this.extractFriendlyIssuer(details.cert.issuerSubject) 
      : existing.issuer;

    // isVulnerable: true if ANY known vulnerability is present
    const isVulnerable = !!(
      details?.heartbleed ||
      details?.poodle ||
      (details?.poodleTls !== undefined && details.poodleTls > 0) ||
      details?.vulnBeast ||
      details?.freak ||
      details?.logjam ||
      details?.drownVulnerable
    );

    // Live Truth Audit: Sync expiration dates from the actual handshake
    const validFrom = details?.cert?.notBefore ? new Date(details.cert.notBefore).toISOString() : existing.validFrom;
    const validTo = details?.cert?.notAfter ? new Date(details.cert.notAfter).toISOString() : existing.validTo;
    const daysUntilExpiry = validTo && validTo !== "Unknown"
      ? Math.ceil((new Date(validTo).getTime() - Date.now()) / (1000 * 60 * 60 * 24))
      : existing.daysUntilExpiry;

    const updated: SslCertificate = {
      ...existing,
      deepScanStatus: "ready",
      grade: endpoint.grade ?? existing.grade,
      issuer,
      protocol: protocolStr,
      validFrom,
      validTo,
      daysUntilExpiry,
      // Correct SSL Labs v3 field paths
      keySize: details?.key?.size ?? existing.keySize,
      keyAlgorithm: details?.key?.alg ?? existing.keyAlgorithm,
      signatureAlgorithm: details?.cert?.sigAlg ?? existing.signatureAlgorithm,
      // TLS version: check name="TLS" AND version="1.3"
      tls13Enabled: details?.protocols
        ? details.protocols.some((p) => p.name === "TLS" && p.version === "1.3")
        : existing.tls13Enabled,
      tls12Enabled: details?.protocols
        ? details.protocols.some((p) => p.name === "TLS" && p.version === "1.2")
        : existing.tls12Enabled,
      forwardSecrecy: details?.forwardSecrecy !== undefined
        ? details.forwardSecrecy >= 2  // 2=DH+ECDHE (good), 4=robust
        : existing.forwardSecrecy,
      ocspStapling: details?.ocspStapling ?? existing.ocspStapling,
      alpnSupported: Array.isArray(details?.alpnProtocols) && details!.alpnProtocols.length > 0,
      isVulnerable,
      recommendation: this.buildDeepRecommendation(existing.recommendation, endpoint.grade, details),
    };

    await this.cache.put(cacheKey, JSON.stringify(updated), {
      expirationTtl: CACHE_TTL_SECONDS,
    });

    // Also update R2/D1 if this was a brand scan
    const domain = cacheKey.replace("ssl:", "");
    await this.persistDeepScanToStorage(domain, updated);
  }

  /** Update R2 and D1 with deep scan results so historical data is accurate */
  private async persistDeepScanToStorage(domain: string, updatedSsl: SslCertificate): Promise<void> {
    try {
      const persistInfo = await this.cache.get<ScanPersistenceInfo>(`ssl:persist:${domain}`, "json");
      if (!persistInfo || !this.r2 || !this.db) return;

      // Update the R2 object with new SSL data
      const r2Object = await this.r2.get(persistInfo.r2Key);
      if (r2Object) {
        const scanResult = (await r2Object.json()) as any;
        scanResult.ssl = updatedSsl;
        await this.r2.put(persistInfo.r2Key, JSON.stringify(scanResult), {
          httpMetadata: { contentType: "application/json" },
        });
      }

      // Update ssl_json in D1
      await this.db.prepare(
        `UPDATE scans SET ssl_json = ? WHERE id = ?`,
      )
        .bind(JSON.stringify(updatedSsl), persistInfo.scanId)
        .run();

      // Clean up persistence key
      await this.cache.delete(`ssl:persist:${domain}`);
    } catch {
      // Non-critical — KV still has the data for quick reads
    }
  }

  private async markDeepScanFailed(cacheKey: string): Promise<void> {
    const existing = await this.cache.get<SslCertificate>(cacheKey, "json");
    if (!existing) return;
    existing.deepScanStatus = "failed";
    await this.cache.put(cacheKey, JSON.stringify(existing), {
      expirationTtl: CACHE_TTL_SECONDS,
    });
  }

  private buildDeepRecommendation(
    baseRec: string | undefined,
    grade: string | undefined,
    details: SslLabsEndpointDetails | undefined,
  ): string | undefined {
    const recs: string[] = [];
    if (baseRec) recs.push(baseRec);

    if (grade === "F" || grade === "M") {
      recs.push("CRITICAL: Major SSL vulnerabilities detected. Review SSL Labs report for immediate fixes.");
    } else if (grade?.startsWith("B")) {
      recs.push("Upgrade to TLS 1.3 and disable legacy ciphers to achieve an A+ grade.");
    } else if (grade?.startsWith("C") || grade?.startsWith("D")) {
      recs.push("Poor SSL configuration. Disable TLS 1.0/1.1 and weak cipher suites.");
    }

    if (details?.heartbleed) recs.push("URGENT: Heartbleed vulnerability detected! Patch OpenSSL immediately and revoke all certificates.");
    if (details?.poodle || (details?.poodleTls !== undefined && details.poodleTls > 0)) recs.push("WARNING: POODLE vulnerability detected. Disable SSLv3 and TLS 1.0.");
    if (details?.freak) recs.push("WARNING: FREAK vulnerability detected. Disable export-grade cipher suites.");
    if (details?.logjam) recs.push("WARNING: Logjam vulnerability detected. Use 2048-bit+ DH parameters.");
    if (details?.drownVulnerable) recs.push("WARNING: DROWN vulnerability detected. Disable SSLv2 on all servers sharing this key.");

    return recs.length > 0 ? recs.join(" ") : undefined;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  // ── Fast Track ─────────────────────────────────────────────────────────────

  /**
   * Fast Certificate Retrieval — all sources in parallel, first valid wins.
   * 1. CertSpotter (CT log API, fast)
   * 2. crt.sh (CT log search, slower but comprehensive)
   * + Apex Domain retry if subdomain fails
   */
  private async fetchCertWithFallbacks(domain: string): Promise<CertSpotterEntry | null> {
    const ts = Date.now();
    const apex = this.dns.getApexDomain(domain);
    const isSubdomain = domain !== apex;

    // Fire ALL sources in parallel — domain + apex at the same time, no sequential retry
    const sources: Promise<CertSpotterEntry | null>[] = [
      this.fetchCertFromCertSpotter(domain, ts),
      this.fetchCertFromCrtSh(domain),
    ];
    // If subdomain, also try apex in parallel (not sequentially!)
    if (isSubdomain) {
      sources.push(this.fetchCertFromCertSpotter(apex, ts));
      sources.push(this.fetchCertFromCrtSh(apex));
    }

    const settled = await Promise.allSettled(sources);
    const results: CertSpotterEntry[] = [];
    for (const res of settled) {
      if (res.status === "fulfilled" && res.value) {
        results.push(res.value);
      }
    }

    if (results.length === 0) return null;

    // Filter to currently valid certs
    const validResults = results.filter(r => new Date(r.not_after).getTime() > ts);
    const pool = validResults.length > 0 ? validResults : results;

    // Prefer Google Trust Services (common for Cloudflare sites)
    const gts = pool.find(r => r.issuer?.friendly_name?.includes("Google") || r.issuer?.name?.includes("GTS"));
    if (gts) return gts;

    // Pick the cert with the latest expiry (most likely to be currently served)
    return pool.sort((a, b) => new Date(b.not_after).getTime() - new Date(a.not_after).getTime())[0];
  }

  private async fetchSslLabsFastCache(domain: string, ts: number): Promise<Partial<SslCertificate> | null> {
    const url = `https://api.ssllabs.com/api/v3/analyze?host=${domain}&publish=off&startNew=off&fromCache=on&all=done&_cb=${ts}`;
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(3000) });
      if (!response.ok) return null;
      const data = await response.json() as SslLabsResponse;
      
      if (data.status === "READY" && data.endpoints?.[0]?.details) {
        const endpoint = data.endpoints[0];
        const details = endpoint.details;
        
        const latestProtocol = details?.protocols?.[0];
        const protocolStr = latestProtocol ? `${latestProtocol.name} ${latestProtocol.version}` : null;
        
        const isVulnerable = !!(
          details?.heartbleed ||
          details?.poodle ||
          (details?.poodleTls !== undefined && details.poodleTls > 0) ||
          details?.vulnBeast ||
          details?.freak ||
          details?.logjam ||
          details?.drownVulnerable
        );

        // Extract cert validity from real TLS handshake data (most accurate source)
        const certNotBefore = details?.cert?.notBefore ? new Date(details.cert.notBefore).toISOString() : undefined;
        const certNotAfter = details?.cert?.notAfter ? new Date(details.cert.notAfter).toISOString() : undefined;
        const certDaysLeft = certNotAfter
          ? Math.ceil((new Date(certNotAfter).getTime() - Date.now()) / (1000 * 60 * 60 * 24))
          : undefined;
        const certIssuer = details?.cert?.issuerSubject
          ? this.extractFriendlyIssuer(details.cert.issuerSubject)
          : undefined;
        const certSubject = details?.cert?.altNames?.[0] ?? undefined;

        return {
          // Cert dates from real TLS handshake — overrides CT log data
          subject: certSubject,
          issuer: certIssuer,
          validFrom: certNotBefore,
          validTo: certNotAfter,
          daysUntilExpiry: certDaysLeft,
          grade: endpoint.grade || null,
          protocol: protocolStr || null,
          keySize: details?.key?.size || null,
          keyAlgorithm: details?.key?.alg || null,
          signatureAlgorithm: details?.cert?.sigAlg || null,
          tls13Enabled: details?.protocols?.some((p) => p.name === "TLS" && p.version === "1.3") ?? null,
          tls12Enabled: details?.protocols?.some((p) => p.name === "TLS" && p.version === "1.2") ?? null,
          forwardSecrecy: details?.forwardSecrecy !== undefined ? details.forwardSecrecy >= 2 : null,
          ocspStapling: details?.ocspStapling ?? null,
          alpnSupported: Array.isArray(details?.alpnProtocols) && details.alpnProtocols.length > 0,
          isVulnerable,
          deepScanStatus: "ready",
          recommendation: this.buildDeepRecommendation(undefined, endpoint.grade, details),
        };
      }
      return null;
    } catch {
      return null;
    }
  }

  private async fetchCertFromCrtSh(domain: string): Promise<CertSpotterEntry | null> {
    const url = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json&exclude=expired`;
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(4000) });
      if (!response.ok) return null;

      const data = await response.json() as any[];
      if (!Array.isArray(data) || data.length === 0) return null;

      const now = Date.now();

      // Filter to currently valid certs, pick the one with furthest expiry
      const validCerts = data
        .filter((e: any) => {
          const notAfter = new Date(e.not_after).getTime();
          const notBefore = new Date(e.not_before).getTime();
          return !isNaN(notAfter) && !isNaN(notBefore) && notAfter > now && notBefore <= now;
        })
        .sort((a: any, b: any) => new Date(b.not_after).getTime() - new Date(a.not_after).getTime());

      const best = validCerts[0] ?? data[0];
      if (!best) return null;

      return {
        id: String(best.id),
        dns_names: [domain],
        issuer: { name: best.issuer_name, friendly_name: this.extractFriendlyIssuer(best.issuer_name) },
        not_before: best.not_before,
        not_after: best.not_after,
        cert_sha256: "",
      };
    } catch {
      return null;
    }
  }

  /**
   * Query CertSpotter (high-performance CT log API) for the currently active certificate.
   * Much faster and more reliable than crt.sh.
   */
  private async fetchCertFromCertSpotter(
    domain: string,
    ts: number,
  ): Promise<CertSpotterEntry | null> {
    const url = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=false&expand=issuer&expand=dns_names&limit=25&_cb=${ts}`;

    try {
      const response = await fetch(url, {
        signal: AbortSignal.timeout(3500),
        headers: { 
          Accept: "application/json",
          "User-Agent": BROWSER_UA
        },
      });

      if (!response.ok) return null;

      const data = (await response.json()) as CertSpotterEntry[];
      if (!Array.isArray(data) || data.length === 0) return null;

      const now = Date.now();

      // Filter to currently active (not expired, already valid) certs
      const activeCerts = data.filter((e) => {
        const notAfter = new Date(e.not_after).getTime();
        const notBefore = new Date(e.not_before).getTime();
        return !isNaN(notAfter) && !isNaN(notBefore) && notAfter > now && notBefore <= now;
      });

      // Pick the cert with the LATEST expiry — most likely to be the currently served one
      if (activeCerts.length > 0) {
        return activeCerts.sort((a, b) => new Date(b.not_after).getTime() - new Date(a.not_after).getTime())[0];
      }
      // No active cert found — return null instead of an expired one
      return null;
    } catch {
      return null;
    }
  }

  private async probeHttps(domain: string): Promise<{
    connected: boolean;
    hstsHeader: string | null;
    altSvc: string | null;
    supportsH3: boolean;
  } | null> {
    try {
      const response = await fetch(`https://${domain}`, {
        method: "HEAD",
        redirect: "follow",
        signal: AbortSignal.timeout(5000),
      });

      const altSvc = response.headers.get("alt-svc");
      // Alt-Svc: h3=":443" indicates HTTP/3 (QUIC) support — implies TLS 1.3
      const supportsH3 = !!altSvc && (altSvc.includes("h3=") || altSvc.includes("h3-"));

      return {
        connected: response.url.startsWith("https://"),
        hstsHeader: response.headers.get("strict-transport-security"),
        altSvc,
        supportsH3,
      };
    } catch {
      return null;
    }
  }

  // ── Result Building ────────────────────────────────────────────────────────

  private buildResult(
    domain: string,
    cert: CertSpotterEntry | null,
    probe: { connected: boolean; hstsHeader: string | null; altSvc: string | null; supportsH3: boolean } | null,
  ): SslCertificate {
    const validFrom = cert?.not_before ?? null;
    const validTo = cert?.not_after ?? null;

    const daysUntilExpiry = validTo
      ? Math.ceil((new Date(validTo).getTime() - Date.now()) / (1000 * 60 * 60 * 24))
      : null;

    const hstsEnabled = !!probe?.hstsHeader;
    const hstsMaxAge = probe?.hstsHeader ? this.parseHstsMaxAge(probe.hstsHeader) : null;

    // If the server supports H3 (via Alt-Svc), it must support TLS 1.3
    // A successful HTTPS connection proves at least TLS 1.2
    const tls13FromProbe = probe?.supportsH3 ? true : null;
    const tls12FromProbe = probe?.connected ? true : null;
    // H3 support implies ALPN negotiation is working
    const alpnFromProbe = probe?.supportsH3 ? true : null;

    return {
      subject: cert?.dns_names[0] ?? domain,
      issuer: cert?.issuer.friendly_name || (cert ? this.extractFriendlyIssuer(cert.issuer.name) : "Unknown"),
      validFrom: cert?.not_before ?? "Unknown",
      validTo: cert?.not_after ?? "Unknown",
      daysUntilExpiry,
      grade: null,          // filled by deep scan
      protocol: tls13FromProbe ? "TLS 1.3" : (tls12FromProbe ? "TLS 1.2+" : null),
      keyAlgorithm: null,   // filled by deep scan
      keySize: null,        // filled by deep scan
      signatureAlgorithm: null, // filled by deep scan
      hstsEnabled,
      isVulnerable: null,   // filled by deep scan
      forwardSecrecy: null, // filled by deep scan
      ocspStapling: null,
      alpnSupported: alpnFromProbe,
      tls13Enabled: tls13FromProbe,
      tls12Enabled: tls12FromProbe,
      ctCompliant: cert ? true : null,
      caaRecordPresent: null,
      deepScanStatus: "pending",
      recommendation: this.generateFastRecommendation({ daysUntilExpiry, hstsEnabled, hstsMaxAge, connected: probe?.connected ?? false }),
    };
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  private extractFriendlyIssuer(issuerName: string): string {
    if (!issuerName) return "Unknown Authority";
    
    // Normalize string: handle both "O=Name, CN=Name" and slash formats "/C=US/O=Name"
    const normalized = issuerName.replaceAll("/", ",").replaceAll(" /", ",");
    
    // Priority 1: Organization (O=) — The gold standard for friendly names
    const oMatch = normalized.match(/O=([^,]+)/i);
    if (oMatch && oMatch[1].trim()) {
      let org = oMatch[1].trim()
        .replace(/^"|"$/g, "") // remove quotes
        .replace(/ Inc\.?| Ltd\.?| LLC| Corporation| Co\.| Corp\./gi, ""); // Clean common suffixes
      
      // Special sanitization for common CAs to keep them concise
      if (org.includes("Let's Encrypt")) return "Let's Encrypt";
      if (org.includes("Google Trust Services")) return "Google Trust Services";
      if (org.includes("DigiCert")) return "DigiCert";
      if (org.includes("Sectigo")) return "Sectigo";
      if (org.includes("Cloudflare")) return "Cloudflare Inc.";
      return org;
    }

    // Priority 2: Common Name (CN=) — Fallback if Organization is missing
    const cnMatch = normalized.match(/CN=([^,]+)/i);
    if (cnMatch && cnMatch[1].trim()) {
      return cnMatch[1].trim().replace(/^"|"$/g, "");
    }

    // Priority 3: First component (for legacy formats)
    const firstPart = normalized.split(",").find(p => p.includes("="));
    if (firstPart) {
      return firstPart.split("=")[1]?.trim() || normalized;
    }

    return issuerName;
  }

  private parseIssuerCn(issuerName: string): string {
    return this.extractFriendlyIssuer(issuerName);
  }

  private parseHstsMaxAge(header: string): number | null {
    const match = header.match(/max-age=(\d+)/i);
    return match ? parseInt(match[1], 10) : null;
  }

  private generateFastRecommendation(data: {
    daysUntilExpiry: number | null;
    hstsEnabled: boolean;
    hstsMaxAge: number | null;
    connected: boolean;
  }): string | undefined {
    const recs: string[] = [];

    if (!data.connected) {
      recs.push("CRITICAL: HTTPS connection failed. Ensure SSL is installed correctly.");
    }

    if (data.daysUntilExpiry !== null) {
      if (data.daysUntilExpiry < 0) {
        recs.push("CRITICAL: SSL certificate has EXPIRED. Renew immediately.");
      } else if (data.daysUntilExpiry < 15) {
        recs.push(`URGENT: Certificate expires in ${data.daysUntilExpiry} days. Renew immediately.`);
      } else if (data.daysUntilExpiry < 30) {
        recs.push(`WARNING: Certificate expires in ${data.daysUntilExpiry} days. Plan renewal soon.`);
      }
    }

    if (!data.hstsEnabled) {
      recs.push("Enable HSTS (Strict-Transport-Security) to enforce secure connections.");
    } else if (data.hstsMaxAge !== null && data.hstsMaxAge < 31536000) {
      recs.push("Increase HSTS max-age to at least 1 year (31536000s) for best security.");
    }

    return recs.length > 0 ? recs.join(" ") : "SSL certificate is valid and properly configured.";
  }
}
