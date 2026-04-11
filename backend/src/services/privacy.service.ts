export class PrivacyService {
  public analyzePrivacy(html: string): {
    trackingPixels: string[];
    hasPrivacyPolicy: boolean;
    hasTermsOfService: boolean;
  } {
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
      { name: "Mixpanel", pattern: /cdn\.mxpnl\.com|api\.mixpanel\.com/i },
      { name: "Segment", pattern: /cdn\.segment\.com\/analytics/i },
      { name: "Plausible", pattern: /plausible\.io\/js/i },
      { name: "Heap Analytics", pattern: /cdn\.heapanalytics\.com/i },
      { name: "Amplitude", pattern: /cdn\.amplitude\.com/i },
      { name: "FullStory", pattern: /fullstory\.com\/s\/fs\.js/i },
      { name: "Pinterest Tag", pattern: /pintrk|s\.pinimg\.com\/ct\/core\.js/i },
      { name: "Snap Pixel", pattern: /tr\.snapchat\.com/i },
      { name: "Twitter Pixel", pattern: /static\.ads-twitter\.com\/uwt\.js/i },
    ];

    for (const pixel of pixelPatterns) {
      if (pixel.pattern.test(html)) {
        trackingPixels.push(pixel.name);
      }
    }

    // Check for privacy policy — look for actual links/pages, not just the word "privacy"
    const hasPrivacyPolicy =
      /href=["'][^"']*privacy[- ]?(policy|statement|notice)[^"']*["']/i.test(html) ||
      /href=["'][^"']*\/privacy[^"']*["']/i.test(html) ||
      /href=["'][^"']*cookie[- ]?policy[^"']*["']/i.test(html) ||
      /href=["'][^"']*data[- ]?protection[^"']*["']/i.test(html) ||
      /<a[^>]*>.*?(privacy\s*(policy|statement|notice)|cookie\s*policy|data\s*protection).*?<\/a>/i.test(html);

    // Check for terms of service — look for actual links/pages
    const hasTermsOfService =
      /href=["'][^"']*terms[- ]?of[- ]?(service|use)[^"']*["']/i.test(html) ||
      /href=["'][^"']*\/terms[^"']*["']/i.test(html) ||
      /href=["'][^"']*(user[- ]?agreement|legal[- ]?notice|disclaimer|eula)[^"']*["']/i.test(html) ||
      /href=["'][^"']*terms[- ]?and[- ]?conditions[^"']*["']/i.test(html) ||
      /<a[^>]*>.*?(terms\s*(of\s*)?(service|use|conditions)|user\s*agreement|legal\s*notice|disclaimer|t&c|eula).*?<\/a>/i.test(html);

    return {
      trackingPixels,
      hasPrivacyPolicy,
      hasTermsOfService,
    };
  }
}
