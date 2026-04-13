export class PrivacyService {
  public async analyzePrivacy(html: string, baseUrl: string): Promise<{
    trackingPixels: string[];
    hasPrivacyPolicy: boolean;
    hasTermsOfService: boolean;
    policyAnalysis?: {
      verified: boolean;
      containsGdprLinks: boolean;
      containsCcpaLinks: boolean;
      lastCheckedAt: string;
    };
  }> {
    const trackingPixels: string[] = [];
    const pixelPatterns = [
      { name: "Facebook Pixel", pattern: /connect\.facebook\.net\/[^/]+\/fbevents\.js/i },
      { name: "Google Tag Manager", pattern: /googletagmanager\.com\/gtm\.js/i },
      { name: "Google Analytics (v4)", pattern: /googletagmanager\.com\/gtag\/js/i },
      { name: "Hotjar", pattern: /static\.hotjar\.com\/c\/hotjar-/i },
      { name: "HubSpot", pattern: /js\.hs-scripts\.com/i },
      { name: "TikTok Pixel", pattern: /analytics\.tiktok\.com/i },
      { name: "LinkedIn Insight", pattern: /snap\.licdn\.com\/li\.lms-analytics/i },
      { name: "Microsoft Clarity", pattern: /clarity\.ms\/tag/i },
      { name: "Segment", pattern: /cdn\.segment\.com\/analytics/i },
      { name: "Plausible", pattern: /plausible\.io\/js/i },
    ];

    for (const pixel of pixelPatterns) {
      if (pixel.pattern.test(html)) trackingPixels.push(pixel.name);
    }

    const policyUrlMatch = html.match(/href=["']([^"']*(?:privacy|cookie|data-protection)[^"']*)["']/i);
    const policyUrl = policyUrlMatch ? this.normalizeUrl(policyUrlMatch[1], baseUrl) : null;

    const hasPrivacyPolicy = !!policyUrl;
    const hasTermsOfService = /href=["'][^"']*(?:terms|condition|legal|disclaimer)[^"']*["']/i.test(html);

    let policyAnalysis;
    if (policyUrl) {
      policyAnalysis = await this.deepAnalyzePolicy(policyUrl);
    }

    return {
      trackingPixels,
      hasPrivacyPolicy,
      hasTermsOfService,
      policyAnalysis,
    };
  }

  private async deepAnalyzePolicy(url: string): Promise<any> {
    try {
      const resp = await fetch(url, { signal: AbortSignal.timeout(5000) });
      if (!resp.ok) return { verified: false, containsGdprLinks: false, containsCcpaLinks: false };
      
      const text = await resp.text();
      const snippet = text.slice(0, 30000).toLowerCase();

      return {
        verified: true,
        containsGdprLinks: snippet.includes("gdpr") || snippet.includes("general data protection regulation") || snippet.includes("european union"),
        containsCcpaLinks: snippet.includes("ccpa") || snippet.includes("california consumer privacy act") || snippet.includes("california resident"),
        lastCheckedAt: new Date().toISOString(),
      };
    } catch {
      return { verified: false, containsGdprLinks: false, containsCcpaLinks: false };
    }
  }

  private normalizeUrl(url: string, base: string): string {
    if (url.startsWith("http")) return url;
    const origin = new URL(base).origin;
    if (url.startsWith("/")) return `${origin}${url}`;
    return `${origin}/${url}`;
  }
}
