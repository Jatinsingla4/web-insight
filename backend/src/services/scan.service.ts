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
    const parsedUrl = new URL(url);
    const domain = parsedUrl.hostname;

    onProgress?.({ scanId, step: "scanning", progress: 0 });

    // Phase 1: Resolve A record quickly for IP, then fire everything in parallel
    let ipAddress: string | null = null;
    try {
      // 3s strict timeout for initial IP resolution
      const timeoutPromise = new Promise<null>((_, reject) => 
        setTimeout(() => reject(new Error("DNS Timeout")), 3000)
      );
      
      ipAddress = await Promise.race([
        this.dns.quickResolveA(domain),
        timeoutPromise
      ]);
    } catch {
      // DNS A record failed or timed out — continue without IP
    }

    // Phase 2: Parallel Discovery & Baseline Scans
    const [
      techStackResult,
      dnsResult,
      sslResult,
      securityResult,
      htmlResponse,
      connectivityResult,
      ipLocationResult,
      ipBlacklistedResult,
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

    return {
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

    // 1. Insert completed scan record
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
        JSON.stringify({
          security: result.security,
          cookieAudit: result.cookieAudit,
          vulnerabilityExposure: result.vulnerabilityExposure,
          trustAudit: result.trustAudit,
          connectivity: result.connectivity,
          emailSecurity: result.emailSecurity,
          privacyAudit: result.privacyAudit,
          techStackHealth: result.techStackHealth,
        }),
        r2Key
      )
      .run();

    // 2. Store in R2
    await this.env.R2.put(r2Key, JSON.stringify(result), {
      httpMetadata: { contentType: "application/json" },
      customMetadata: { brandId, scanId },
    });

    // 3. Update brand pointer
    await this.env.DB.prepare(
      `UPDATE brands
       SET last_scan_id = ?,
           last_scanned_at = ?,
           updated_at = datetime('now')
       WHERE id = ?`,
    )
      .bind(scanId, result.scannedAt, brandId)
      .run();

    return scanId;
  }

  /** Brand scan — runs the scan and persists results. */
  async brandScan(
    brandId: string,
    domain: string,
    onProgress?: (p: ScanProgress) => void,
    ctx?: { waitUntil: (p: Promise<any>) => void },
  ): Promise<string> {
    const scanId = generateId();

    // Insert pending scan record
    await this.env.DB.prepare(
      `INSERT INTO scans (id, brand_id, status, started_at)
       VALUES (?, ?, 'running', datetime('now'))`,
    )
      .bind(scanId, brandId)
      .run();

    try {
      const url = `https://${domain}`;
      const result = await this.quickScan(url, onProgress, true, ctx);

      // Store raw response in R2
      const r2Key = `scans/${brandId}/${scanId}.json`;
      await this.env.R2.put(r2Key, JSON.stringify(result), {
        httpMetadata: { contentType: "application/json" },
        customMetadata: { brandId, scanId },
      });

      // Update scan record with results
      await this.env.DB.prepare(
        `UPDATE scans
         SET status = 'completed',
             tech_stack_json = ?,
             dns_json = ?,
             ssl_json = ?,
             extra_data_json = ?,
             raw_response_r2_key = ?,
             completed_at = datetime('now')
         WHERE id = ?`,
      )
        .bind(
          JSON.stringify(result.techStack),
          JSON.stringify(result.dns),
          JSON.stringify(result.ssl),
          JSON.stringify({
            security: result.security,
            cookieAudit: result.cookieAudit,
            vulnerabilityExposure: result.vulnerabilityExposure,
            trustAudit: result.trustAudit,
            connectivity: result.connectivity,
            emailSecurity: result.emailSecurity,
            privacyAudit: result.privacyAudit,
            techStackHealth: result.techStackHealth,
          }),
          r2Key,
          scanId,
        )
        .run();

      // Update brand's last scan reference
      await this.env.DB.prepare(
        `UPDATE brands
         SET last_scan_id = ?,
             last_scanned_at = datetime('now'),
             updated_at = datetime('now')
         WHERE id = ?`,
      )
        .bind(scanId, brandId)
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
             completed_at = datetime('now')
         WHERE id = ?`,
      )
        .bind(message, scanId)
        .run();

      throw error;
    }
  }
}
