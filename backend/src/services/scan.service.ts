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

    // Phase 2: ALL services in parallel — including IP analysis (no sequential Phase 3)
    const [
      techStack,
      dnsResult,
      ssl,
      security,
      vulnerabilities,
      htmlResponse,
      connectivity,
      ipLocation,
      ipBlacklisted,
    ] = await Promise.allSettled([
      this.techStack.analyze(url, force),
      this.dns.lookup(domain, force),
      this.ssl.analyze(domain, force, ctx),
      this.security.analyzeHeaders(url),
      this.vulnerability.checkExposures(url),
      fetch(url, {
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 DNSChecker/1.0",
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.9",
          "Referer": "https://www.google.com/",
        },
        signal: AbortSignal.timeout(6000)
      }).then((res) => res.text()),
      this.connectivity.traceRedirects(domain),
      ipAddress ? this.ip.analyze(ipAddress, undefined, force) : Promise.resolve(null),
      ipAddress ? this.dns.checkReputation(ipAddress) : Promise.resolve(null),
    ]);

    const techStackResult = techStack.status === "fulfilled" ? techStack.value : { techs: [], headers: null };
    const ipLocationResult = ipLocation.status === "fulfilled" ? ipLocation.value : null;
    const dnsData = dnsResult.status === "fulfilled" ? dnsResult.value : null;

    // Build server info from parallel results
    let server = undefined;
    if (ipAddress) {
      server = {
        ip: ipAddress,
        location: ipLocationResult,
        blacklisted: ipBlacklisted.status === "fulfilled" ? ipBlacklisted.value : null,
      };
    }

    const techStackValue = techStackResult.techs;
    const techStackHealth = this.techStack.analyzeHealth(techStackValue);
    const spfRecord = dnsData?.records.find(
      (r) => r.type === "TXT" && r.data.toLowerCase().startsWith("v=spf1"),
    )?.data;
    const dmarcRecord = dnsData?.records.find(
      (r) => r.type === "TXT" && r.data.toLowerCase().startsWith("v=dmarc1"),
    )?.data;

    onProgress?.({ scanId, step: "completed", progress: 100 });

    return {
      url,
      domain,
      scannedAt: new Date().toISOString(),
      techStack: techStackValue,
      techStackHealth,
      dns: dnsData ?? { records: [], nameservers: [] },
      ssl: ssl.status === "fulfilled" ? ssl.value : null,
      server,
      security:
        security.status === "fulfilled"
          ? { headers: security.value.headers, score: security.value.score }
          : undefined,
      cookieAudit: security.status === "fulfilled" ? security.value.cookies : undefined,
      vulnerabilityExposure: vulnerabilities.status === "fulfilled" ? vulnerabilities.value : undefined,
      trustAudit:
        htmlResponse.status === "fulfilled"
          ? this.trust.analyzeScripts(htmlResponse.value, domain)
          : undefined,
      connectivity:
        connectivity.status === "fulfilled"
          ? {
              redirectChain: connectivity.value.chain,
              wwwRedirectStatus: connectivity.value.wwwStatus,
              isHstsPreloadReady: security.status === "fulfilled" ? security.value.isHstsPreloadReady : false,
              socialLinks:
                htmlResponse.status === "fulfilled"
                  ? this.connectivity.auditSocialLinks(htmlResponse.value)
                  : [],
            }
          : undefined,
      emailSecurity: {
        spf: this.email.analyzeSpf(spfRecord ?? ""),
        dmarc: this.email.analyzeDmarc(dmarcRecord ?? ""),
      },
      privacyAudit:
        htmlResponse.status === "fulfilled"
          ? this.privacy.analyzePrivacy(htmlResponse.value)
          : undefined,
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
