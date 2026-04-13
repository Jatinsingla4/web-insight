import type { SslCertificate } from "@dns-checker/shared";
import { CACHE_TTL_SECONDS } from "@dns-checker/shared";
import type { DnsService } from "./dns.service";
import { connect } from "cloudflare:sockets";

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
  // Extra fields populated only by direct TCP socket extraction (id === "tls-direct")
  tlsVersion?: string | null;         // negotiated TLS 1.2 version string
  cipherSuiteName?: string | null;    // e.g. "ECDHE-RSA-AES128-GCM-SHA256"
  forwardSecrecy?: boolean | null;    // inferred from cipher suite
  signatureAlgorithm?: string | null; // e.g. "SHA256withRSA", "SHA256withECDSA"
  keyAlgorithm?: string | null;       // "RSA", "EC", "Ed25519"
  keySize?: number | null;            // 2048 / 4096 for RSA, 256 / 384 for EC
  chainLength?: number;               // number of certs in the TLS chain
  sctCount?: number;                  // number of SCTs (CT log proofs)
  isSelfSigned?: boolean;             // issuer bytes === subject bytes
  // Parallel detection results
  tls13Detected?: boolean | null;     // from separate TLS 1.3-only connection attempt
  alpnProtocol?: string | null;       // ALPN protocol selected by server (e.g. "h2")
  ocspStapled?: boolean;
  alpnSupported?: boolean;
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
    const maxRetries = 30; // up to ~5 mins total (10s + 29×10s = 300s)

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

        // Check every 10s to catch "READY" as soon as possible
        await this.sleep(10000);
      } catch {
        // Network error or timeout — keep trying unless last attempt
        if (attempt === maxRetries - 1) {
          await this.markDeepScanFailed(cacheKey);
        }
        await this.sleep(10000);
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

    const updated: any = {
      ...existing,
      deepScanStatus: "ready",
      grade: endpoint.grade ?? existing.grade,
      issuer,
      protocol: protocolStr,
      validFrom,
      validTo,
      daysUntilExpiry,
      // Enhanced Metrics
      ocspStapling: details?.ocspStapling ?? existing.ocspStapling,
      ctCompliant: endpoint.details?.cert?.altNames !== undefined, // Simple heuristic for deep scan
      // Correct SSL Labs v3 field paths
      keySize: details?.key?.size ?? existing.keySize,
      keyAlgorithm: details?.key?.alg ?? existing.keyAlgorithm,
      signatureAlgorithm: details?.cert?.sigAlg ?? existing.signatureAlgorithm,
      // TLS version: check name="TLS" AND version="1.3"
      tls13Enabled: details?.protocols
        ? details.protocols.some((p: any) => p.name === "TLS" && p.version === "1.3")
        : existing.tls13Enabled,
      tls12Enabled: details?.protocols
        ? details.protocols.some((p: any) => p.name === "TLS" && p.version === "1.2")
        : existing.tls12Enabled,
      forwardSecrecy: details?.forwardSecrecy !== undefined
        ? details.forwardSecrecy >= 2  // 2=DH+ECDHE (good), 4=robust
        : existing.forwardSecrecy,
      alpnSupported: Array.isArray(details?.alpnProtocols) && details.alpnProtocols.length > 0,
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
   * Fast Certificate Retrieval — real TLS handshake first, CT logs as fallback.
   * Priority: ssl-checker.io (real TLS) > CertSpotter (CT) > crt.sh (CT)
   */
  private async fetchCertWithFallbacks(domain: string): Promise<CertSpotterEntry | null> {
    const ts = Date.now();
    const apex = this.dns.getApexDomain(domain);
    const isSubdomain = domain !== apex;

    // All sources in parallel — direct TCP socket + ssl-checker.io + CT logs
    const sources: Promise<CertSpotterEntry | null>[] = [
      this.fetchCertViaTcpSocket(domain),            // Direct TLS via TCP (highest accuracy, no third-party)
      this.fetchCertFromTlsCheck(domain),            // ssl-checker.io (backup real TLS)
      this.fetchCertFromCertSpotter(domain, ts),     // CT log
      this.fetchCertFromCrtSh(domain),               // CT log fallback
    ];
    if (isSubdomain) {
      sources.push(this.fetchCertFromCertSpotter(apex, ts));
    }

    const settled = await Promise.allSettled(sources);
    const results: CertSpotterEntry[] = [];
    for (const res of settled) {
      if (res.status === "fulfilled" && res.value) {
        results.push(res.value);
      }
    }

    if (results.length === 0) return null;

    // Priority 1: Direct TCP socket result — most accurate, no third-party dependency
    const tlsDirect = results.find(r => r.id === "tls-direct");
    if (tlsDirect) return tlsDirect; 

    // Priority 2: ssl-checker.io real TLS handshake
    const tlsLive = results.find(r => r.id === "tls-live");
    if (tlsLive && new Date(tlsLive.not_after).getTime() > ts) return tlsLive;

    // Priority 3: CT logs — only used for subject/issuer, dates will be null in buildResult
    const validResults = results.filter(r => new Date(r.not_after).getTime() > ts);
    const pool = validResults.length > 0 ? validResults : results;
    return pool.sort((a, b) => new Date(b.not_after).getTime() - new Date(a.not_after).getTime())[0];
  }

  /** Real TLS handshake via ssl-checker.io — returns actual served cert, not CT log data. */
  private async fetchCertFromTlsCheck(domain: string): Promise<CertSpotterEntry | null> {
    try {
      const response = await fetch(`https://ssl-checker.io/api/v1/check/${encodeURIComponent(domain)}`, {
        headers: { "User-Agent": BROWSER_UA },
        signal: AbortSignal.timeout(3000),
      });
      if (!response.ok) return null;

      const data = await response.json() as any;
      if (data.status !== "ok" || !data.result) return null;

      const r = data.result;
      return {
        id: "tls-live",
        dns_names: r.cert_sans
          ? r.cert_sans.split(";").map((s: string) => s.replace("DNS:", "").trim()).filter(Boolean)
          : [domain],
        issuer: {
          name: `O=${r.issuer_o ?? ""}, CN=${r.issuer_cn ?? ""}`,
          friendly_name: this.extractFriendlyIssuer(`O=${r.issuer_o ?? ""}, CN=${r.issuer_cn ?? ""}`),
        },
        not_before: new Date(r.valid_from).toISOString(),
        not_after: new Date(r.valid_till).toISOString(),
        cert_sha256: r.cert_sha1 || "",
      };
    } catch {
      return null;
    }
  }

  /**
   * Direct TLS certificate extraction via Cloudflare TCP socket.
   * No third-party API — we open a raw TCP connection, send a TLS 1.2 ClientHello,
   * and read the server's Certificate from the unencrypted TLS 1.2 handshake.
   * This is the most reliable source because it hits the live server directly.
   */
  private async fetchCertViaTcpSocket(domain: string): Promise<CertSpotterEntry | null> {
    try {
      return await Promise.race([
        this._doTcpCertFetch(domain),
        new Promise<null>((_, reject) =>
          setTimeout(() => reject(new Error("tcp-timeout")), 5000),
        ),
      ]);
    } catch {
      return null;
    }
  }

  private async _doTcpCertFetch(domain: string): Promise<CertSpotterEntry | null> {
    // Run TLS 1.2 cert+ALPN fetch and TLS 1.3 detection in parallel —
    // both open separate TCP connections simultaneously, zero extra latency.
    const [handshake, tls13Supported] = await Promise.all([
      this._fetchTls12Handshake(domain),
      tlsDetectTls13(domain),
    ]);
    if (!handshake) return null;
    return tlsParseCertificate(handshake, domain, tls13Supported);
  }

  private async _fetchTls12Handshake(domain: string): Promise<TlsHandshakeResult | null> {
    const socket = connect({ hostname: domain, port: 443 });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    try {
      await writer.write(tlsBuildClientHello(domain));
      return await tlsReadHandshake(reader);
    } finally {
      reader.cancel().catch(() => {});
      writer.releaseLock();
      socket.close().catch(() => {});
    }
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
    // CRITICAL: Only use dates from real TLS handshake sources.
    // CT log sources (CertSpotter, crt.sh) have stale/wrong dates for frequently
    // rotated certs. CT logs are only reliable for subject, issuer, and ctCompliant.
    // Fallback to any available certificate dates (API or Live)
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

    // Direct TCP socket extra fields — available instantly, no SSL Labs needed
    const isDirect = cert?.id === "tls-direct";
    const certKeyAlg    = isDirect ? (cert?.keyAlgorithm ?? null) : null;
    const certKeySize   = isDirect ? (cert?.keySize ?? null) : null;
    const certSigAlg    = isDirect ? (cert?.signatureAlgorithm ?? null) : null;
    const certFs        = isDirect ? (cert?.forwardSecrecy ?? null) : null;

    // TLS 1.3: parallel detection result > Alt-Svc probe (H3 implies TLS 1.3)
    const tls13Direct   = isDirect ? (cert?.tls13Detected ?? null) : null;
    const tls13Enabled  = tls13Direct ?? (probe?.supportsH3 ? true : null);

    // ALPN: server-selected protocol from ALPN extension in ServerHello
    const alpnDirect    = isDirect ? (cert?.alpnProtocol ?? null) : null;
    const alpnSupported = alpnDirect != null ? true : (probe?.supportsH3 ? true : null);

    // Protocol string: if TLS 1.3 confirmed, show that; else TLS 1.2 from cert or probe
    const certTlsVersion = isDirect ? (cert?.tlsVersion ?? null) : null;
    const protocol = tls13Enabled ? "TLS 1.3" : (certTlsVersion ?? (tls12FromProbe ? "TLS 1.2" : null));

    return {
      subject: cert?.dns_names[0] ?? domain,
      issuer: cert?.issuer.friendly_name || (cert ? this.extractFriendlyIssuer(cert.issuer.name) : "Unknown"),
      validFrom: validFrom ?? "Unknown",
      validTo: validTo ?? "Unknown",
      daysUntilExpiry,
      grade: null,
      protocol,
      keyAlgorithm: certKeyAlg,
      keySize: certKeySize,
      signatureAlgorithm: certSigAlg,
      hstsEnabled,
      isVulnerable: null,                   // requires SSL Labs deep scan
      forwardSecrecy: certFs,
      ocspStapling: null,                   // requires SSL Labs deep scan
      alpnSupported,
      tls13Enabled,
      tls12Enabled: tls12FromProbe,
      ctCompliant: isDirect ? (cert.sctCount !== undefined ? cert.sctCount > 0 : true) : (cert ? true : null),
      caaRecordPresent: null,
      // Direct TCP extras
      cipherSuiteName: isDirect ? (cert.cipherSuiteName ?? null) : null,
      chainLength:     isDirect ? (cert.chainLength ?? null) : null,
      sctCount:        isDirect ? (cert.sctCount ?? null) : null,
      isSelfSigned:    isDirect ? (cert.isSelfSigned ?? null) : null,
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

// ═══════════════════════════════════════════════════════════════════════════════
// Direct TLS Certificate Extraction — Pure functions, no class needed
// Strategy: send TLS 1.2-only ClientHello → server Certificate is unencrypted
//           → parse X.509 DER → extract all fields without SSL Labs
// ═══════════════════════════════════════════════════════════════════════════════

// ── Lookup Tables ──────────────────────────────────────────────────────────────

const SIG_ALG_OIDS: Record<string, string> = {
  "1.2.840.113549.1.1.5":  "SHA1withRSA",
  "1.2.840.113549.1.1.11": "SHA256withRSA",
  "1.2.840.113549.1.1.12": "SHA384withRSA",
  "1.2.840.113549.1.1.13": "SHA512withRSA",
  "1.2.840.10045.4.3.2":   "SHA256withECDSA",
  "1.2.840.10045.4.3.3":   "SHA384withECDSA",
  "1.2.840.10045.4.3.4":   "SHA512withECDSA",
  "1.3.101.112":            "Ed25519",
  "1.2.840.113549.1.1.10": "RSASSA-PSS",
};

const KEY_ALG_OIDS: Record<string, string> = {
  "1.2.840.113549.1.1.1": "RSA",
  "1.2.840.10045.2.1":    "EC",
  "1.3.101.112":          "Ed25519",
  "1.3.101.110":          "X25519",
};

// EC curve OID → key size in bits
const EC_CURVE_SIZE: Record<string, number> = {
  "1.2.840.10045.3.1.7": 256,   // P-256 / secp256r1
  "1.3.132.0.34":        384,   // P-384 / secp384r1
  "1.3.132.0.35":        521,   // P-521 / secp521r1
  "1.3.132.0.10":        256,   // secp256k1
};

// Cipher suites that provide forward secrecy (ECDHE or DHE key exchange)
const FS_CIPHERS = new Set([
  0xC02B, 0xC02C, 0xC02F, 0xC030,   // ECDHE-{ECDSA,RSA} GCM
  0xC009, 0xC00A, 0xC013, 0xC014,   // ECDHE CBC
  0xC023, 0xC024, 0xC027, 0xC028,   // ECDHE CBC SHA2
  0xCCA8, 0xCCA9, 0xCCAA,           // ChaCha20-Poly1305
  0x0033, 0x0039, 0x0067, 0x006B,   // DHE-RSA
  0x1301, 0x1302, 0x1303, 0x1304, 0x1305, // TLS 1.3 (all have FS)
]);

const CIPHER_SUITE_NAMES: Record<number, string> = {
  0xC02B: "ECDHE-ECDSA-AES128-GCM-SHA256",
  0xC02C: "ECDHE-ECDSA-AES256-GCM-SHA384",
  0xC02F: "ECDHE-RSA-AES128-GCM-SHA256",
  0xC030: "ECDHE-RSA-AES256-GCM-SHA384",
  0xCCA8: "ECDHE-RSA-CHACHA20-POLY1305",
  0xCCA9: "ECDHE-ECDSA-CHACHA20-POLY1305",
  0x009C: "RSA-AES128-GCM-SHA256",
  0x0035: "RSA-AES256-SHA",
  0x1301: "TLS_AES_128_GCM_SHA256",
  0x1302: "TLS_AES_256_GCM_SHA384",
  0x1303: "TLS_CHACHA20_POLY1305_SHA256",
};

// ── Byte Utilities ─────────────────────────────────────────────────────────────

function tlsConcatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) { result.set(a, offset); offset += a.length; }
  return result;
}

function tlsUint16BE(n: number): Uint8Array {
  return new Uint8Array([(n >> 8) & 0xFF, n & 0xFF]);
}

function tlsUint24BE(n: number): Uint8Array {
  return new Uint8Array([(n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]);
}

// ── TLS 1.2 ClientHello Builder ────────────────────────────────────────────────
// We intentionally cap at TLS 1.2 — server Certificate is unencrypted in 1.2.
// In TLS 1.3 the Certificate is encrypted after the key exchange.

function tlsBuildClientHello(domain: string): Uint8Array {
  const serverNameBytes = new TextEncoder().encode(domain);
  const snLen = serverNameBytes.length;

  // SNI — required for virtual hosting (multiple certs on same IP)
  const sniExt = new Uint8Array(9 + snLen);
  const sniView = new DataView(sniExt.buffer);
  sniView.setUint16(0, 0x0000);
  sniView.setUint16(2, snLen + 5);
  sniView.setUint16(4, snLen + 3);
  sniView.setUint8(6, 0x00);
  sniView.setUint16(7, snLen);
  sniExt.set(serverNameBytes, 9);

  const supportedGroups = new Uint8Array([
    0x00, 0x0A, 0x00, 0x08, 0x00, 0x06,
    0x00, 0x1D, 0x00, 0x17, 0x00, 0x18,  // x25519, secp256r1, secp384r1
  ]);

  const ecPointFormats = new Uint8Array([0x00, 0x0B, 0x00, 0x02, 0x01, 0x00]);

  const sigAlgs = new Uint8Array([
    0x00, 0x0D, 0x00, 0x12, 0x00, 0x10,
    0x04, 0x03, 0x08, 0x04, 0x04, 0x01,
    0x05, 0x03, 0x08, 0x05, 0x05, 0x01,
    0x08, 0x06, 0x06, 0x01,
  ]);

  // status_request extension — server sends CertificateStatus if OCSP stapling active
  const statusRequest = new Uint8Array([0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00]);
  // ALPN extension — server echoes selected protocol in ServerHello if HTTP/2 supported
  // Protocol list: "h2" (3 bytes) + "http/1.1" (9 bytes) = 12 bytes
  // Extension data: 2-byte list-length prefix + 12 = 14 bytes
  const alpnRequest = new Uint8Array([
    0x00, 0x10,                                              // type: ALPN
    0x00, 0x0E,                                              // ext data length: 14
    0x00, 0x0C,                                              // ProtocolNameList length: 12
    0x02, 0x68, 0x32,                                        // "h2"  (len=2)
    0x08, 0x68, 0x74, 0x74, 0x70, 0x2F, 0x31, 0x2E, 0x31,  // "http/1.1" (len=8)
  ]);

  // TLS 1.2-only cipher suites — no TLS_AES_* which would signal 1.3 support
  const cipherSuites = new Uint8Array([
    0xC0, 0x2C, 0xC0, 0x2B, 0xC0, 0x30, 0xC0, 0x2F,
    0x00, 0x9C, 0x00, 0x35, 0x00, 0xFF,
  ]);

  const extensions = tlsConcatBytes(sniExt, supportedGroups, ecPointFormats, sigAlgs, statusRequest, alpnRequest);
  const body = tlsConcatBytes(
    new Uint8Array([0x03, 0x03]),
    crypto.getRandomValues(new Uint8Array(32)),
    new Uint8Array([0x00]),
    tlsUint16BE(cipherSuites.length), cipherSuites,
    new Uint8Array([0x01, 0x00]),
    tlsUint16BE(extensions.length), extensions,
  );
  const handshake = tlsConcatBytes(new Uint8Array([0x01]), tlsUint24BE(body.length), body);
  return tlsConcatBytes(new Uint8Array([0x16, 0x03, 0x01]), tlsUint16BE(handshake.length), handshake);
}

// ── TLS Handshake Result ───────────────────────────────────────────────────────

interface TlsHandshakeResult {
  certDer: Uint8Array;
  chainLength: number;
  tlsVersionId: number;       // 0x0303 = TLS 1.2, 0x0304 = TLS 1.3
  cipherSuiteId: number;      // selected cipher suite
  ocspStapled: boolean;
  alpnSupported: boolean;
  alpnProtocol: string | null; // e.g. "h2" or "http/1.1" — null if server didn't echo ALPN
}

// ── TLS Record Reader ──────────────────────────────────────────────────────────
// Accumulates raw TCP bytes, parses TLS records, captures ServerHello metadata
// and the server's leaf certificate DER from the Certificate message (0x0B).

async function tlsReadHandshake(
  reader: ReadableStreamDefaultReader<Uint8Array>,
): Promise<TlsHandshakeResult | null> {
  let buf: Uint8Array = new Uint8Array(0);
  let tlsVersionId = 0x0303;     // default: TLS 1.2
  let cipherSuiteId = 0;
  let ocspStapled = false;
  let alpnSupported = false;
  let alpnProtocol: string | null = null;
  let result: { certDer: Uint8Array; chainLength: number } | null = null;

  for (let i = 0; i < 20; i++) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value?.length) continue;

    buf = tlsConcatBytes(buf, new Uint8Array(value));

    let offset = 0;
    while (offset + 5 <= buf.length) {
      const contentType = buf[offset];
      const recordLen   = (buf[offset + 3] << 8) | buf[offset + 4];
      if (offset + 5 + recordLen > buf.length) break;

      const recordData = buf.slice(offset + 5, offset + 5 + recordLen);
      offset += 5 + recordLen;

      if (contentType === 0x15) return null;  // Alert

      if (contentType === 0x16) {
        // Scan all handshake messages inside this record
        let hOff = 0;
        while (hOff + 4 <= recordData.length) {
          const hType = recordData[hOff];
          const hLen  = (recordData[hOff + 1] << 16) | (recordData[hOff + 2] << 8) | recordData[hOff + 3];
          if (hOff + 4 + hLen > recordData.length) break;

          const hBody = recordData.slice(hOff + 4, hOff + 4 + hLen);

          if (hType === 0x02 && hLen >= 35) {
            // ServerHello — parse extensions for cipher, TLS version, and ALPN
            const sessionIdLen = hBody[34];
            const csOff = 35 + sessionIdLen;
            if (csOff + 2 <= hBody.length) {
              cipherSuiteId = (hBody[csOff] << 8) | hBody[csOff + 1];
              tlsVersionId = (hBody[0] << 8) | hBody[1];
              // Parse extensions: csOff+2=cipher, +3=compression, +4..+5=extTotalLen
              if (csOff + 5 < hBody.length) {
                const extTotalLen = (hBody[csOff + 3] << 8) | hBody[csOff + 4];
                let eOff = csOff + 5;
                while (eOff + 4 <= csOff + 5 + extTotalLen && eOff + 4 <= hBody.length) {
                  const extType = (hBody[eOff] << 8) | hBody[eOff + 1];
                  const extLen  = (hBody[eOff + 2] << 8) | hBody[eOff + 3];
                  if (extType === 0x002B && extLen === 2) {
                    // supported_versions — real negotiated TLS version (overrides legacy field)
                    tlsVersionId = (hBody[eOff + 4] << 8) | hBody[eOff + 5];
                  } else if (extType === 0x0010 && extLen >= 4) {
                    // ALPN extension — server echoes selected protocol
                    // Format: u16 protoListLen { u8 nameLen, nameBytes }
                    const protoListLen = (hBody[eOff + 4] << 8) | hBody[eOff + 5];
                    if (protoListLen >= 1 && eOff + 6 < hBody.length) {
                      const nameLen = hBody[eOff + 6];
                      if (nameLen > 0 && eOff + 7 + nameLen <= hBody.length) {
                        alpnProtocol = new TextDecoder().decode(hBody.slice(eOff + 7, eOff + 7 + nameLen));
                        alpnSupported = true;
                      }
                    }
                  }
                  eOff += 4 + extLen;
                }
              }
            }
          } else if (hType === 0x0B) {
            // Certificate message
            result = tlsExtractCertInfo(hBody);
          } else if (hType === 0x16 || hType === 0x08) {
            // Handshake message Type 0x08/0x16 = CertificateStatus (OCSP Response)
            ocspStapled = true;
          } else if (hType === 0x0E || (hType === 0x0C && tlsVersionId === 0x0303)) {
            // ServerHelloDone (0x0E) or ServerKeyExchange (0x0C) — stop reading, we have what we need
            if (result) {
              return { ...result, tlsVersionId, cipherSuiteId, ocspStapled, alpnSupported, alpnProtocol };
            }
          }

          hOff += 4 + hLen;
        }
      }
    }

    if (offset > 0) buf = buf.slice(offset);
  }

  return null;
}

function tlsExtractCertInfo(body: Uint8Array): { certDer: Uint8Array; chainLength: number } | null {
  if (body.length < 6) return null;
  // 3 bytes: list length
  const listLen = (body[0] << 16) | (body[1] << 8) | body[2];
  let offset = 3;
  let chainLength = 0;
  let firstCertDer: Uint8Array | null = null;

  while (offset + 3 <= 3 + listLen && offset + 3 <= body.length) {
    const certLen = (body[offset] << 16) | (body[offset + 1] << 8) | body[offset + 2];
    offset += 3;
    if (certLen === 0 || offset + certLen > body.length) break;

    if (chainLength === 0) firstCertDer = body.slice(offset, offset + certLen);
    chainLength++;
    offset += certLen;
  }

  if (!firstCertDer || chainLength === 0) return null;
  return { certDer: firstCertDer, chainLength };
}

// ── ASN.1 / DER Parser ────────────────────────────────────────────────────────

interface Asn1Node {
  tag: number;
  value: Uint8Array;
  end: number;
}

function asn1Read(buf: Uint8Array, offset: number): Asn1Node | null {
  if (offset + 2 > buf.length) return null;
  const tag = buf[offset++];
  let len = buf[offset++];
  if (len & 0x80) {
    const nb = len & 0x7F;
    if (nb === 0 || nb > 4 || offset + nb > buf.length) return null;
    len = 0;
    for (let i = 0; i < nb; i++) len = (len << 8) | buf[offset++];
  }
  if (offset + len > buf.length) return null;
  return { tag, value: buf.slice(offset, offset + len), end: offset + len };
}

function asn1Children(buf: Uint8Array): Asn1Node[] {
  const nodes: Asn1Node[] = [];
  let offset = 0;
  while (offset < buf.length) {
    const node = asn1Read(buf, offset);
    if (!node) break;
    nodes.push(node);
    offset = node.end;
  }
  return nodes;
}

function asn1ParseTime(node: Asn1Node): string | null {
  const s = new TextDecoder().decode(node.value);
  if (node.tag === 0x17 && s.length >= 12) {
    const yy = parseInt(s.slice(0, 2), 10);
    const yyyy = yy >= 50 ? 1900 + yy : 2000 + yy;
    return `${yyyy}-${s.slice(2, 4)}-${s.slice(4, 6)}T${s.slice(6, 8)}:${s.slice(8, 10)}:${s.slice(10, 12)}Z`;
  }
  if (node.tag === 0x18 && s.length >= 14) {
    return `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T${s.slice(8, 10)}:${s.slice(10, 12)}:${s.slice(12, 14)}Z`;
  }
  return null;
}

function asn1ParseOid(buf: Uint8Array): string {
  if (buf.length < 1) return "";
  const parts: number[] = [Math.floor(buf[0] / 40), buf[0] % 40];
  let val = 0;
  for (let i = 1; i < buf.length; i++) {
    val = (val << 7) | (buf[i] & 0x7F);
    if (!(buf[i] & 0x80)) { parts.push(val); val = 0; }
  }
  return parts.join(".");
}

function asn1ParseDn(buf: Uint8Array): Record<string, string> {
  const result: Record<string, string> = {};
  for (const rdn of asn1Children(buf)) {
    if (rdn.tag !== 0x31) continue;
    for (const atv of asn1Children(rdn.value)) {
      if (atv.tag !== 0x30) continue;
      const [oidNode, valNode] = asn1Children(atv.value);
      if (!oidNode || !valNode) continue;
      const oid = asn1ParseOid(oidNode.value);
      const val = new TextDecoder().decode(valNode.value);
      if (oid === "2.5.4.3")  result["CN"] = val;
      else if (oid === "2.5.4.10") result["O"] = val;
    }
  }
  return result;
}

// SubjectPublicKeyInfo → { alg, keySize }
function asn1ParseSpki(buf: Uint8Array): { alg: string; keySize: number | null } | null {
  const spki = asn1Read(buf, 0);
  if (!spki || spki.tag !== 0x30) return null;

  const [algIdNode, keyBitsNode] = asn1Children(spki.value);
  if (!algIdNode || algIdNode.tag !== 0x30) return null;

  const [algOidNode, paramsNode] = asn1Children(algIdNode.value);
  if (!algOidNode || algOidNode.tag !== 0x06) return null;

  const algOid = asn1ParseOid(algOidNode.value);
  const alg = KEY_ALG_OIDS[algOid] ?? algOid;

  if (alg === "RSA") {
    // Key size = bit length of modulus in RSAPublicKey
    if (!keyBitsNode || keyBitsNode.tag !== 0x03) return { alg, keySize: null };
    // BIT STRING: first byte is "unused bits" padding count, skip it
    const rsaSeq = asn1Read(keyBitsNode.value, 1);
    if (!rsaSeq || rsaSeq.tag !== 0x30) return { alg, keySize: null };
    const modulusNode = asn1Read(rsaSeq.value, 0);
    if (!modulusNode || modulusNode.tag !== 0x02) return { alg, keySize: null };
    // INTEGER: leading 0x00 byte is added when high bit is set (positive sign)
    const mod = modulusNode.value;
    const sigBytes = mod[0] === 0x00 ? mod.length - 1 : mod.length;
    return { alg, keySize: sigBytes * 8 };
  }

  if (alg === "EC") {
    // Curve is the OID in parameters
    if (!paramsNode || paramsNode.tag !== 0x06) return { alg, keySize: null };
    const curveOid = asn1ParseOid(paramsNode.value);
    return { alg, keySize: EC_CURVE_SIZE[curveOid] ?? null };
  }

  // Ed25519, X25519 — fixed 256-bit
  if (algOid === "1.3.101.112" || algOid === "1.3.101.110") {
    return { alg, keySize: 256 };
  }

  return { alg, keySize: null };
}

// Extensions SEQUENCE → OCSP URL from Authority Information Access (OID 1.3.6.1.5.5.7.1.1)
function asn1ParseAiaOcsp(extsBuf: Uint8Array): string | null {
  for (const ext of asn1Children(extsBuf)) {
    if (ext.tag !== 0x30) continue;
    const kids = asn1Children(ext.value);
    if (!kids[0] || kids[0].tag !== 0x06) continue;
    if (asn1ParseOid(kids[0].value) !== "1.3.6.1.5.5.7.1.1") continue;  // AIA OID

    const octet = kids.find(k => k.tag === 0x04);
    if (!octet) continue;

    const aiaSeq = asn1Read(octet.value, 0);
    if (!aiaSeq || aiaSeq.tag !== 0x30) continue;

    for (const ad of asn1Children(aiaSeq.value)) {
      if (ad.tag !== 0x30) continue;
      const [methodNode, locNode] = asn1Children(ad.value);
      if (!methodNode || methodNode.tag !== 0x06) continue;
      if (asn1ParseOid(methodNode.value) !== "1.3.6.1.5.5.7.48.1") continue; // OCSP OID
      if (!locNode || locNode.tag !== 0x86) continue; // [6] uniformResourceIdentifier
      return new TextDecoder().decode(locNode.value);
    }
  }
  return null;
}

// Extensions SEQUENCE → SCT count from CT Precertificate SCTs (OID 1.3.6.1.4.1.11129.2.4.2)
function asn1ParseSctCount(extsBuf: Uint8Array): number {
  for (const ext of asn1Children(extsBuf)) {
    if (ext.tag !== 0x30) continue;
    const kids = asn1Children(ext.value);
    if (!kids[0] || kids[0].tag !== 0x06) continue;
    if (asn1ParseOid(kids[0].value) !== "1.3.6.1.4.1.11129.2.4.2") continue;

    const octet = kids.find(k => k.tag === 0x04);
    if (!octet || octet.value.length < 4) continue;

    // Structure: OCTET STRING { u16 listLen { u16 sctLen, N bytes SCT }* }
    // Parse inner OCTET STRING that holds the raw SCT list
    const inner = asn1Read(octet.value, 0);
    const sctBuf = inner?.tag === 0x04 ? inner.value : octet.value;

    const listLen = (sctBuf[0] << 8) | sctBuf[1];
    let count = 0;
    let pos = 2;
    while (pos + 2 <= 2 + listLen && pos + 2 <= sctBuf.length) {
      const sctLen = (sctBuf[pos] << 8) | sctBuf[pos + 1];
      pos += 2 + sctLen;
      count++;
    }
    return count;
  }
  return 0;
}

// Extensions SEQUENCE → SANs (Subject Alternative Names, OID 2.5.29.17)
function asn1ParseSans(extsBuf: Uint8Array): string[] {
  for (const ext of asn1Children(extsBuf)) {
    if (ext.tag !== 0x30) continue;
    const kids = asn1Children(ext.value);
    if (!kids[0] || kids[0].tag !== 0x06) continue;
    if (asn1ParseOid(kids[0].value) !== "2.5.29.17") continue;

    const octet = kids.find(k => k.tag === 0x04);
    if (!octet) continue;

    const sanSeq = asn1Read(octet.value, 0);
    if (!sanSeq) continue;

    return asn1Children(sanSeq.value)
      .filter(n => n.tag === 0x82)   // dNSName [2]
      .map(n => new TextDecoder().decode(n.value));
  }
  return [];
}

// ── X.509 Certificate Parser ───────────────────────────────────────────────────
// Parses everything we need from the DER cert in a single pass.

function tlsParseCertificate(handshake: TlsHandshakeResult, domain: string, tls13Supported: boolean): CertSpotterEntry | null {
  try {
    const { certDer, chainLength, tlsVersionId, cipherSuiteId, ocspStapled } = handshake;

    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    const certSeq = asn1Read(certDer, 0);
    if (!certSeq || certSeq.tag !== 0x30) return null;

    const certChildren = asn1Children(certSeq.value);
    // [0] TBSCertificate, [1] signatureAlgorithm, [2] signatureValue
    const tbsNode = certChildren[0];
    const outerSigAlgNode = certChildren[1];
    if (!tbsNode || tbsNode.tag !== 0x30) return null;

    // Outer signature algorithm
    let signatureAlgorithm: string | null = null;
    if (outerSigAlgNode?.tag === 0x30) {
      const oidNode = asn1Read(outerSigAlgNode.value, 0);
      if (oidNode?.tag === 0x06) {
        signatureAlgorithm = SIG_ALG_OIDS[asn1ParseOid(oidNode.value)] ?? null;
      }
    }

    // TBSCertificate fields
    const fields = asn1Children(tbsNode.value);
    let i = 0;
    if (fields[i]?.tag === 0xA0) i++;  // version [0]
    i++;                                // serialNumber
    i++;                                // inner signatureAlgorithm (same as outer)

    const issuerNode   = fields[i++];  // Name
    const validityNode = fields[i++];  // Validity
    const subjectNode  = fields[i++];  // Name
    const spkiNode     = fields[i++];  // SubjectPublicKeyInfo
    const extWrapper   = fields.find(f => f.tag === 0xA3);  // [3] Extensions

    // Validity dates
    if (!validityNode || validityNode.tag !== 0x30) return null;
    const [nbNode, naNode] = asn1Children(validityNode.value);
    const notBefore = nbNode ? asn1ParseTime(nbNode) : null;
    const notAfter  = naNode ? asn1ParseTime(naNode)  : null;
    if (!notBefore || !notAfter) return null;

    // Issuer and subject
    const issuerDn  = issuerNode  ? asn1ParseDn(issuerNode.value)  : {};
    const subjectDn = subjectNode ? asn1ParseDn(subjectNode.value) : {};
    const issuerStr = issuerDn["O"] || issuerDn["CN"] || "Unknown";
    const subjectCN = subjectDn["CN"] || domain;

    // Self-signed: issuer raw bytes === subject raw bytes
    const isSelfSigned = !!(issuerNode && subjectNode &&
      issuerNode.value.length === subjectNode.value.length &&
      issuerNode.value.every((b, idx) => b === subjectNode.value[idx]));

    // Public key info
    const spkiInfo = spkiNode ? asn1ParseSpki(spkiNode.value) : null;

    // Extensions
    let dnsNames: string[] = [subjectCN];
    let sctCount = 0;
    if (extWrapper) {
      const extsSeq = asn1Read(extWrapper.value, 0);
      if (extsSeq?.tag === 0x30) {
        const sans = asn1ParseSans(extsSeq.value);
        if (sans.length > 0) dnsNames = sans;
        sctCount = asn1ParseSctCount(extsSeq.value);
      }
    }

    // TLS handshake metadata
    const tlsVersion      = tlsVersionId === 0x0304 ? "TLS 1.3" : "TLS 1.2";
    const cipherSuiteName = CIPHER_SUITE_NAMES[cipherSuiteId] ?? `0x${cipherSuiteId.toString(16).padStart(4, "0")}`;
    const forwardSecrecy  = FS_CIPHERS.has(cipherSuiteId);

    return {
      id: "tls-direct",
      dns_names: dnsNames,
      issuer: { name: issuerStr, friendly_name: issuerStr },
      not_before: notBefore,
      not_after: notAfter,
      cert_sha256: "",
      // Handshake metadata
      tlsVersion,
      cipherSuiteName,
      forwardSecrecy,
      // Cert metadata
      signatureAlgorithm,
      keyAlgorithm: spkiInfo?.alg ?? null,
      keySize:      spkiInfo?.keySize ?? null,
      chainLength,
      sctCount,
      isSelfSigned,
      ocspStapled: handshake.ocspStapled,
      alpnSupported: handshake.alpnSupported,
      alpnProtocol: handshake.alpnProtocol,
      tls13Detected: tls13Supported,
    };
  } catch {
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TLS 1.3 Detection — separate TCP connection with TLS 1.3-only ClientHello.
// Runs in parallel with the cert fetch (zero extra wall-clock time).
// Strategy: advertise ONLY TLS 1.3 + key_share — if server responds with a
// ServerHello containing supported_versions=0x0304 we know it supports TLS 1.3.
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Builds a TLS 1.3-only ClientHello.
 * Key differences vs the 1.2 hello:
 *   - supported_versions extension with TLS 1.3 only (0x0304)
 *   - key_share extension with a random x25519 public key (required in 1.3)
 *   - Only TLS 1.3 cipher suites (TLS_AES_*)
 */
function tlsBuildTls13ClientHello(domain: string): Uint8Array {
  const serverNameBytes = new TextEncoder().encode(domain);
  const snLen = serverNameBytes.length;

  // SNI extension (same structure as TLS 1.2)
  const sniExt = new Uint8Array(9 + snLen);
  const sniView = new DataView(sniExt.buffer);
  sniView.setUint16(0, 0x0000); // type: SNI
  sniView.setUint16(2, snLen + 5);
  sniView.setUint16(4, snLen + 3);
  sniView.setUint8(6, 0x00);    // hostname type
  sniView.setUint16(7, snLen);
  sniExt.set(serverNameBytes, 9);

  // supported_versions: TLS 1.3 only
  const supportedVersions = new Uint8Array([
    0x00, 0x2B,        // type: supported_versions
    0x00, 0x03,        // ext length: 3
    0x02,              // versions list length: 2 bytes
    0x03, 0x04,        // TLS 1.3 (0x0304)
  ]);

  // supported_groups: x25519 only
  const supportedGroups = new Uint8Array([
    0x00, 0x0A,        // type: supported_groups
    0x00, 0x04,        // ext length: 4
    0x00, 0x02,        // group list length: 2
    0x00, 0x1D,        // x25519
  ]);

  // key_share: single x25519 entry (random 32-byte ephemeral public key).
  // TLS 1.3 requires key_share to be present in ClientHello.
  const ephemeralKey = crypto.getRandomValues(new Uint8Array(32));
  const keyShare = tlsConcatBytes(
    new Uint8Array([0x00, 0x33]),  // type: key_share
    tlsUint16BE(38),               // ext length: 2(listLen) + 2(group) + 2(keyLen) + 32 = 38
    tlsUint16BE(36),               // ClientKeyShareList length: 36
    new Uint8Array([0x00, 0x1D]),  // x25519
    tlsUint16BE(32),               // key_exchange length
    ephemeralKey,
  );

  // signature_algorithms (required by RFC 8446)
  const sigAlgs = new Uint8Array([
    0x00, 0x0D,        // type: signature_algorithms
    0x00, 0x0A,        // ext length: 10
    0x00, 0x08,        // list length: 8
    0x04, 0x03,        // ecdsa_secp256r1_sha256
    0x08, 0x04,        // rsa_pss_rsae_sha256
    0x04, 0x01,        // rsa_pkcs1_sha256
    0x08, 0x06,        // rsa_pss_rsae_sha512
  ]);

  // TLS 1.3 cipher suites only
  const cipherSuites = new Uint8Array([
    0x13, 0x01,  // TLS_AES_128_GCM_SHA256
    0x13, 0x02,  // TLS_AES_256_GCM_SHA384
    0x13, 0x03,  // TLS_CHACHA20_POLY1305_SHA256
  ]);

  const extensions = tlsConcatBytes(sniExt, supportedVersions, supportedGroups, keyShare, sigAlgs);
  const body = tlsConcatBytes(
    new Uint8Array([0x03, 0x03]),                     // legacy_version: TLS 1.2 (required by spec)
    crypto.getRandomValues(new Uint8Array(32)),        // random
    new Uint8Array([0x00]),                            // legacy_session_id length: 0
    tlsUint16BE(cipherSuites.length), cipherSuites,
    new Uint8Array([0x01, 0x00]),                      // compression methods: null
    tlsUint16BE(extensions.length), extensions,
  );

  const handshake = tlsConcatBytes(new Uint8Array([0x01]), tlsUint24BE(body.length), body);
  return tlsConcatBytes(new Uint8Array([0x16, 0x03, 0x01]), tlsUint16BE(handshake.length), handshake);
}

/**
 * Reads a ServerHello and returns true if supported_versions = 0x0304 (TLS 1.3).
 * Stops at the first ServerHello (we don't need Certificate or anything after).
 */
async function tlsServerHelloIsTls13(reader: ReadableStreamDefaultReader<Uint8Array>): Promise<boolean> {
  let buf: Uint8Array = new Uint8Array(0);

  for (let i = 0; i < 10; i++) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value?.length) continue;
    buf = tlsConcatBytes(buf, new Uint8Array(value));

    let offset = 0;
    while (offset + 5 <= buf.length) {
      const contentType = buf[offset];
      const recordLen   = (buf[offset + 3] << 8) | buf[offset + 4];
      if (offset + 5 + recordLen > buf.length) break;

      const recordData = buf.slice(offset + 5, offset + 5 + recordLen);
      offset += 5 + recordLen;

      if (contentType === 0x15) return false;  // Alert — server rejected our hello

      if (contentType === 0x16) {
        let hOff = 0;
        while (hOff + 4 <= recordData.length) {
          const hType = recordData[hOff];
          const hLen  = (recordData[hOff + 1] << 16) | (recordData[hOff + 2] << 8) | recordData[hOff + 3];
          if (hOff + 4 + hLen > recordData.length) break;

          if (hType === 0x02 && hLen >= 35) {
            // ServerHello — look for supported_versions extension
            const hBody = recordData.slice(hOff + 4, hOff + 4 + hLen);
            const sessionIdLen = hBody[34];
            const csOff = 35 + sessionIdLen;
            if (csOff + 5 < hBody.length) {
              const extTotalLen = (hBody[csOff + 3] << 8) | hBody[csOff + 4];
              let eOff = csOff + 5;
              while (eOff + 4 <= csOff + 5 + extTotalLen && eOff + 4 <= hBody.length) {
                const extType = (hBody[eOff] << 8) | hBody[eOff + 1];
                const extLen  = (hBody[eOff + 2] << 8) | hBody[eOff + 3];
                if (extType === 0x002B && extLen === 2) {
                  return ((hBody[eOff + 4] << 8) | hBody[eOff + 5]) === 0x0304;
                }
                eOff += 4 + extLen;
              }
            }
            // ServerHello found but no supported_versions — server spoke TLS 1.2
            return false;
          }
          hOff += 4 + hLen;
        }
      }

      if (offset > 0) buf = buf.slice(offset);
    }
  }
  return false;
}

/** Opens a fresh TCP connection and sends a TLS 1.3-only ClientHello. */
async function _tls13Check(domain: string): Promise<boolean> {
  const socket = connect({ hostname: domain, port: 443 });
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  try {
    await writer.write(tlsBuildTls13ClientHello(domain));
    return await tlsServerHelloIsTls13(reader);
  } finally {
    reader.cancel().catch(() => {});
    writer.releaseLock();
    socket.close().catch(() => {});
  }
}

/**
 * Public entry point — wraps _tls13Check with a timeout.
 * Returns false (not true) on any error so missing TLS 1.3 data degrades gracefully.
 */
async function tlsDetectTls13(domain: string): Promise<boolean> {
  try {
    return await Promise.race([
      _tls13Check(domain),
      new Promise<boolean>((_, reject) =>
        setTimeout(() => reject(new Error("tls13-detect-timeout")), 4000),
      ),
    ]);
  } catch {
    return false;
  }
}
