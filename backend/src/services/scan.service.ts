import type { ScanResult } from "@dns-checker/shared";
import { TechStackService } from "./tech-stack.service";
import { DnsService } from "./dns.service";
import { SslService } from "./ssl.service";
import { IpService } from "./ip.service";
import { SecurityService } from "./security.service";
import { VulnerabilityService } from "./vulnerability.service";
import { TrustService } from "./trust.service";
import { ConnectivityService } from "./connectivity.service";
import { EmailService } from "./email.service";
import { PrivacyService } from "./privacy.service";
import { generateId } from "../lib/crypto";
import { assertPublicUrl } from "../lib/ssrf";
import type { Env } from "../lib/env";

export interface ScanProgress {
  scanId: string;
  step: string;
  progress: number;
}

export class ScanService {
  private readonly techStack: TechStackService;
  private readonly dns: DnsService;
  private readonly ssl: SslService;
  private readonly ip: IpService;
  private readonly security: SecurityService;
  private readonly vulnerability: VulnerabilityService;
  private readonly trust: TrustService;
  private readonly connectivity: ConnectivityService;
  private readonly email: EmailService;
  private readonly privacy: PrivacyService;

  constructor(private readonly env: Env) {
    this.techStack = new TechStackService(env.CACHE);
    this.dns = new DnsService(env.CACHE);
    this.ssl = new SslService(env.CACHE, this.dns);
    this.ip = new IpService(env.CACHE);
    this.security = new SecurityService();
    this.vulnerability = new VulnerabilityService();
    this.trust = new TrustService();
    this.connectivity = new ConnectivityService();
    this.email = new EmailService();
    this.privacy = new PrivacyService();
  }

  /** Stateless quick scan — no persistence. */
  async quickScan(
    url: string,
    onProgress?: (p: ScanProgress) => void,
    force = false,
    ctx?: { waitUntil: (p: Promise<any>) => void },
  ): Promise<ScanResult> {
    const scanId = generateId();
    const parsedUrl = assertPublicUrl(url); // SSRF guard
    const domain = parsedUrl.hostname;

    onProgress?.({ scanId, step: "scanning", progress: 0 });

    const cacheKey = `global:scan:v1:${domain}`;

    // 1. Check Global Application Cache
    if (!force) {
      const cached = await this.env.CACHE.get<ScanResult>(cacheKey, "json");
      if (cached) return { ...cached, isCached: true };
    }

    // Phase 1: Parallel DNS resolution + Baseline Scans that do NOT depend on IP
    const ipResolvePromise = this.dns.quickResolveA(domain).catch(() => null);
    
    const [
      techStackResult,
      dnsResult,
      sslResult,
      securityResult,
      htmlResponse,
      connectivityResult,
    ] = await Promise.allSettled([
      this.techStack.analyze(url, force),
      this.dns.lookup(domain, force),
      this.ssl.analyze(domain, force, ctx),
      this.security.analyzeHeaders(url),
      fetch(url, {
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 WebInsight/1.0",
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
          "Referer": "https://www.google.com/",
        },
        signal: AbortSignal.timeout(6000)
      }).then((res) => res.text()),
      this.connectivity.traceRedirects(domain),
    ]);

    // Handle IP resolution result
    const ipAddress = await ipResolvePromise;

    // Phase 2: IP-dependent scans
    const [
      ipLocationResult,
      ipBlacklistedResult,
    ] = await Promise.allSettled([
      ipAddress ? this.ip.analyze(ipAddress, undefined, force) : Promise.resolve(null),
      ipAddress ? this.dns.checkReputation(ipAddress) : Promise.resolve(null),
    ]);

    const techs = techStackResult.status === "fulfilled" ? techStackResult.value.techs : [];
    const html = htmlResponse.status === "fulfilled" ? htmlResponse.value : "";

    // Phase 3: Deep Context-Aware Scans (Depends on Tech & HTML)
    const [
      vulnerabilities,
      privacy,
    ] = await Promise.allSettled([
      this.vulnerability.checkExposures(url, techs),
      this.privacy.analyzePrivacy(html, url),
    ]);

    const dnsData = dnsResult.status === "fulfilled" ? dnsResult.value : null;
    const ipLocData = ipLocationResult.status === "fulfilled" ? ipLocationResult.value : null;

    // Build server info from results
    let server = undefined;
    if (ipAddress) {
      server = {
        ip: ipAddress,
        location: ipLocData,
        blacklisted: ipBlacklistedResult.status === "fulfilled" ? ipBlacklistedResult.value : null,
      };
    }

    const techStackHealth = this.techStack.analyzeHealth(techs);
    const spfRecord = dnsData?.records.find(
      (r) => r.type === "TXT" && r.data.toLowerCase().startsWith("v=spf1"),
    )?.data;
    const dmarcRecord = dnsData?.records.find(
      (r) => r.type === "TXT" && r.data.toLowerCase().startsWith("v=dmarc1"),
    )?.data;

    onProgress?.({ scanId, step: "completed", progress: 100 });

    const secRes = securityResult.status === "fulfilled" ? securityResult.value : null;

    const result: ScanResult = {
      url,
      domain,
      scannedAt: new Date().toISOString(),
      techStack: techs,
      techStackHealth,
      dns: dnsData ?? { records: [], nameservers: [] },
      ssl: sslResult.status === "fulfilled" ? sslResult.value : null,
      server,
      security: secRes ? { headers: secRes.headers, score: secRes.score } : undefined,
      cookieAudit: secRes ? secRes.cookies : undefined,
      vulnerabilityExposure: vulnerabilities.status === "fulfilled" ? vulnerabilities.value : undefined,
      trustAudit: html ? this.trust.analyzeScripts(html, domain) : undefined,
      connectivity: connectivityResult.status === "fulfilled" 
        ? {
            redirectChain: connectivityResult.value.chain,
            wwwRedirectStatus: connectivityResult.value.wwwStatus,
            isHstsPreloadReady: secRes ? secRes.isHstsPreloadReady : false,
            socialLinks: html ? this.connectivity.auditSocialLinks(html) : [],
          }
        : undefined,
      emailSecurity: {
        spf: this.email.analyzeSpf(spfRecord ?? ""),
        dmarc: this.email.analyzeDmarc(dmarcRecord ?? ""),
      },
      privacyAudit: privacy.status === "fulfilled" ? privacy.value : undefined,
    };

    // 4. Persist to Global Application Cache (24-hour TTL)
    ctx?.waitUntil(
      this.env.CACHE.put(cacheKey, JSON.stringify(result), {
        expirationTtl: 86400, // 24 hours
      })
    );

    return result;
  }

  /** 
   * Save an existing scan result (e.g. from a quick scan) as a 
   * brand's official first scan. Instant, no discovery overhead.
   */
  async saveExistingResult(
    brandId: string,
    result: ScanResult
  ): Promise<string> {
    const scanId = generateId();
    const r2Key = `scans/${brandId}/${scanId}.json`;

    const extraDataJson = JSON.stringify(this.extractExtraData(result));

    // 1. Write to R2 first, then DB — if DB fails we delete the orphaned R2 object
    await this.env.R2.put(r2Key, JSON.stringify(result), {
      httpMetadata: { contentType: "application/json" },
      customMetadata: { brandId, scanId },
    });

    try {
      await this.env.DB.prepare(
        `INSERT INTO scans (
          id, brand_id, status, started_at, completed_at,
          tech_stack_json, dns_json, ssl_json, extra_data_json, raw_response_r2_key
        ) VALUES (?, ?, 'completed', ?, ?, ?, ?, ?, ?, ?)`,
      )
        .bind(
          scanId,
          brandId,
          result.scannedAt,
          result.scannedAt,
          JSON.stringify(result.techStack),
          JSON.stringify(result.dns),
          JSON.stringify(result.ssl),
          extraDataJson,
          r2Key
        )
        .run();
    } catch (dbErr) {
      // Roll back R2 object to avoid orphan
      this.env.R2.delete(r2Key).catch(() => {});
      throw dbErr;
    }

    // 3. Update brand pointer
    await this.env.DB.prepare(
      `UPDATE brands
       SET last_scan_id = ?,
           last_scanned_at = ?,
           updated_at = ?
       WHERE id = ?`,
    )
      .bind(scanId, result.scannedAt, new Date().toISOString(), brandId)
      .run();

    // 4. Register SSL persistence so background updates work
    if (result.ssl && result.ssl.deepScanStatus === "scanning") {
      this.ssl.registerPersistence(result.domain, r2Key, scanId, this.env.R2, this.env.DB);
    }

    return scanId;
  }

  /** Brand scan — runs the scan and persists results. */
  async brandScan(
    brandId: string,
    domain: string,
    onProgress?: (p: ScanProgress) => void,
    ctx?: { waitUntil: (p: Promise<any>) => void },
    force = false,
  ): Promise<string> {
    const scanId = generateId();

    // Insert pending scan record
    await this.env.DB.prepare(
      `INSERT INTO scans (id, brand_id, status, started_at, created_at)
       VALUES (?, ?, 'running', ?, ?)`,
    )
      .bind(scanId, brandId, new Date().toISOString(), new Date().toISOString())
      .run();

    try {
      const url = `https://${domain}`;
      // Allow cache usage for brands if available (improves "Instant" feel)
      const result = await this.quickScan(url, onProgress, false, ctx);

      const r2Key = `scans/${brandId}/${scanId}.json`;
      const extraDataJson = JSON.stringify(this.extractExtraData(result));

      // Write R2 first, then DB — on DB failure delete the orphaned R2 object
      await this.env.R2.put(r2Key, JSON.stringify(result), {
        httpMetadata: { contentType: "application/json" },
        customMetadata: { brandId, scanId },
      });

      try {
        await this.env.DB.prepare(
          `UPDATE scans
           SET status = 'completed',
               tech_stack_json = ?,
               dns_json = ?,
               ssl_json = ?,
               extra_data_json = ?,
               raw_response_r2_key = ?,
               completed_at = ?
           WHERE id = ?`,
        )
          .bind(
            JSON.stringify(result.techStack),
            JSON.stringify(result.dns),
            JSON.stringify(result.ssl),
            extraDataJson,
            r2Key,
            new Date().toISOString(),
            scanId,
          )
          .run();
      } catch (dbErr) {
        // Roll back R2 object to avoid orphan
        this.env.R2.delete(r2Key).catch(() => {});
        throw dbErr;
      }

      // Update brand's last scan reference
      await this.env.DB.prepare(
        `UPDATE brands
         SET last_scan_id = ?,
             last_scanned_at = ?,
             updated_at = ?
         WHERE id = ?`,
      )
        .bind(scanId, new Date().toISOString(), new Date().toISOString(), brandId)
        .run();

      // Register persistence so SSL deep scan can update R2/D1 when it completes
      this.ssl.registerPersistence(domain, r2Key, scanId, this.env.R2, this.env.DB);

      return scanId;
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error";
      await this.env.DB.prepare(
        `UPDATE scans
         SET status = 'failed',
             error_message = ?,
             completed_at = ?
         WHERE id = ?`,
      )
        .bind(message, new Date().toISOString(), scanId)
        .run();

      throw error;
    }
  }

  private extractExtraData(result: ScanResult) {
    return {
      security: result.security,
      cookieAudit: result.cookieAudit,
      vulnerabilityExposure: result.vulnerabilityExposure,
      trustAudit: result.trustAudit,
      connectivity: result.connectivity,
      emailSecurity: result.emailSecurity,
      privacyAudit: result.privacyAudit,
      techStackHealth: result.techStackHealth,
    };
  }
}
