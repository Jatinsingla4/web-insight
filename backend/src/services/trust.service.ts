export interface ExternalScriptAudit {
  url: string;
  domain: string;
  hasSri: boolean;
}

export class TrustService {
  public analyzeScripts(html: string, targetDomain: string): {
    externalScripts: ExternalScriptAudit[];
    uniqueDomainsCount: number;
    sriComplianceScore: number;
  } {
    const scripts: ExternalScriptAudit[] = [];
    // Match script tags with external src (http/https)
    const scriptRegex = /<script\b[^>]*?\bsrc=["'](https?:\/\/[^"']+)["'][^>]*?>/gi;

    let match;
    while ((match = scriptRegex.exec(html)) !== null) {
      const fullTag = match[0];
      const url = match[1];

      try {
        const scriptUrl = new URL(url);
        // Only track truly external domains (not subdomains of target)
        if (scriptUrl.hostname !== targetDomain && !scriptUrl.hostname.endsWith(`.${targetDomain}`)) {
          // Validate SRI: must have integrity attribute with a valid hash prefix
          const hasSri = /\bintegrity=["']sha(256|384|512)-/.test(fullTag);

          scripts.push({
            url,
            domain: scriptUrl.hostname,
            hasSri,
          });
        }
      } catch {
        // Skip invalid URLs
      }
    }

    const uniqueDomains = new Set(scripts.map(s => s.domain));
    const sriCount = scripts.filter(s => s.hasSri).length;

    // If no external scripts, score is 100 (nothing to protect against)
    // But we distinguish: 0 scripts = N/A (return 100), >0 scripts = actual compliance %
    const sriScore = scripts.length > 0
      ? Math.round((sriCount / scripts.length) * 100)
      : 100;

    return {
      externalScripts: scripts,
      uniqueDomainsCount: uniqueDomains.size,
      sriComplianceScore: sriScore,
    };
  }
}
