import { assertPublicUrl } from "../lib/ssrf";

export interface ConnectivityAudit {
  redirectChain: string[];
  isHstsPreloadReady: boolean;
  wwwRedirectStatus: "success" | "warning" | "error";
  socialLinks: { platform: string; url: string; isSecure: boolean }[];
}

export class ConnectivityService {
  async traceRedirects(domain: string): Promise<{ chain: string[]; wwwStatus: "success" | "warning" | "error" }> {
    const chain: string[] = [];
    let currentUrl = `http://${domain}`;
    let wwwStatus: "success" | "warning" | "error" = "success";

    try {
      // Trace up to 5 hops to avoid infinite loops
      for (let i = 0; i < 5; i++) {
        assertPublicUrl(currentUrl); // SSRF guard on every hop
        chain.push(currentUrl);
        const response = await fetch(currentUrl, {
          method: "HEAD",
          headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 DNSChecker/1.0",
            "Accept": "*/*",
          },
          redirect: "manual",
          signal: AbortSignal.timeout(5000),
        });

        if (response.status >= 300 && response.status < 400) {
          const nextUrl = response.headers.get("location");
          if (nextUrl) {
            currentUrl = nextUrl.startsWith("http") ? nextUrl : new URL(nextUrl, currentUrl).toString();
            continue;
          }
        }
        break;
      }

      // Audit WWW vs Non-WWW convergence
      const finalUrl = new URL(chain[chain.length - 1]);
      if (domain.startsWith("www.")) {
        if (!finalUrl.hostname.startsWith("www.")) wwwStatus = "warning";
      } else {
        // If they entered non-www, usually it's fine either way, but no redirect is a warning
        if (chain.length === 1) wwwStatus = "warning";
      }
    } catch {
      wwwStatus = "error";
    }

    return { chain, wwwStatus };
  }

  auditSocialLinks(html: string): { platform: string; url: string; isSecure: boolean }[] {
    const socialPlatforms = [
      { name: "Facebook", pattern: /facebook\.com\/[^"'\s]+/gi },
      { name: "Twitter", pattern: /twitter\.com\/[^"'\s]+/gi },
      { name: "X", pattern: /x\.com\/[^"'\s]+/gi },
      { name: "LinkedIn", pattern: /linkedin\.com\/[^"'\s]+/gi },
      { name: "Instagram", pattern: /instagram\.com\/[^"'\s]+/gi },
    ];

    const results: { platform: string; url: string; isSecure: boolean }[] = [];
    
    // Find all <a> tags to check for rel
    const linkRegex = /<a\b[^>]*?\bhref=["'](https?:\/\/[^"']+)["'][^>]*?>(.*?)<\/a>/gi;
    let match;

    while ((match = linkRegex.exec(html)) !== null) {
      const fullTag = match[0];
      const url = match[1];
      
      for (const platform of socialPlatforms) {
        if (platform.pattern.test(url)) {
          const hasNoopener = /\bnoopener\b/i.test(fullTag);
          const hasNoreferrer = /\bnoreferrer\b/i.test(fullTag);
          const isSecure = hasNoopener && hasNoreferrer;
          results.push({
            platform: platform.name,
            url,
            isSecure,
          });
          break; // Avoid double matching same link
        }
      }
    }

    // De-duplicate by URL
    return Array.from(new Map(results.map(r => [r.url, r])).values());
  }
}
