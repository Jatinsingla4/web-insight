import type { TechStackItem } from "@dns-checker/shared";
import { CACHE_TTL_SECONDS } from "@dns-checker/shared";

export class TechStackService {
  constructor(private readonly cache: KVNamespace) {}

  async analyze(url: string, force = false): Promise<{ techs: TechStackItem[], headers: Headers | null }> {
    const cacheKey = `techstack:v2:${url}`;
    if (!force) {
      const cached = await this.cache.get<{ techs: TechStackItem[], headers: any }>(cacheKey, "json");
      if (cached) return { techs: cached.techs, headers: new Headers(cached.headers) };
    }

    const result = await this.detectFromSite(url);

    await this.cache.put(cacheKey, JSON.stringify({
      techs: result.techs,
      headers: Object.fromEntries(result.headers.entries())
    }), {
      expirationTtl: CACHE_TTL_SECONDS,
    });

    return result;
  }

  /**
   * Detect tech stack from HTTP headers + HTML content analysis.
   * No external API dependency — fast and reliable.
   */
  private async detectFromSite(url: string): Promise<{ techs: TechStackItem[], headers: Headers }> {
    const techs: TechStackItem[] = [];

    try {
      const response = await fetch(url, {
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.9",
          "Referer": "https://www.google.com/",
        },
        redirect: "follow",
        signal: AbortSignal.timeout(10000),
      });

      // 1. Analyze response headers
      const headers = response.headers;
      this.detectFromHeaders(headers, techs);

      // 2. Analyze HTML content
      if (headers.get("content-type")?.includes("text/html")) {
        const html = await response.text();
        const snippet = html.slice(0, 500_000); // 500KB Deep Analysis Buffer
        this.detectFromHtml(snippet, techs);
      }
      
      const seen = new Set<string>();
      return {
        techs: techs.filter((t) => {
          const key = t.name.toLowerCase();
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        }),
        headers: headers || new Headers()
      };
    } catch {
      return { techs: [], headers: new Headers() };
    }
  }

  private detectFromHeaders(headers: Headers, techs: TechStackItem[]): void {
    const server = headers.get("server");
    const poweredBy = headers.get("x-powered-by");
    const generator = headers.get("x-generator");

    if (server) techs.push(this.buildItem(server, ["Web servers"]));
    if (poweredBy) techs.push(this.buildItem(poweredBy, ["Programming languages"]));
    if (generator) techs.push(this.buildItem(generator, ["CMS"]));

    // Platform & Infrastructure detection from headers
    if (headers.get("x-vercel-id")) techs.push(this.buildItem("Vercel", ["PaaS"]));
    if (headers.get("cf-ray")) techs.push(this.buildItem("Cloudflare", ["CDN"]));
    if (headers.get("x-amz-cf-id")) techs.push(this.buildItem("Amazon CloudFront", ["CDN"]));
    if (headers.get("x-akamai-transformed") || headers.get("x-akamai-session-info")) techs.push(this.buildItem("Akamai", ["CDN"]));
    if (headers.get("x-dispatcher")) techs.push(this.buildItem("Adobe Experience Manager", ["CMS"]));
    if (headers.get("x-shopify-stage")) techs.push(this.buildItem("Shopify", ["Ecommerce"]));
    if (headers.get("x-github-request-id")) techs.push(this.buildItem("GitHub Pages", ["PaaS"]));
    if (headers.get("x-wix-request-id")) techs.push(this.buildItem("Wix", ["CMS"]));
    if (headers.get("x-fw-hash")) techs.push(this.buildItem("Flywheel", ["Web servers"]));
    if (headers.get("x-drupal-cache")) techs.push(this.buildItem("Drupal", ["CMS"]));
    if (headers.get("x-litespeed-cache")) techs.push(this.buildItem("LiteSpeed", ["Web servers"]));

    // Cookie-based Deep Detection
    const cookies = headers.get("set-cookie") ?? "";
    // CMS Cookies
    if (cookies.includes("wp_")) techs.push(this.buildItem("WordPress", ["CMS"]));
    if (cookies.includes("EPiServer_") || cookies.includes("EPiStateMarker")) techs.push(this.buildItem("Optimizely (EPiServer)", ["CMS"]));
    if (cookies.includes("sc_") || cookies.includes("scSite")) techs.push(this.buildItem("Sitecore", ["CMS"]));
    
    // Ecommerce Cookies & Infrastructure
    if (cookies.includes("dwpersonalization") || cookies.includes("dwanonymous")) techs.push(this.buildItem("Salesforce Commerce Cloud", ["Ecommerce"]));
    if (cookies.includes("JSESSIONID_hybris")) techs.push(this.buildItem("SAP Hybris", ["Ecommerce"]));
    if (cookies.includes("laravel_session")) techs.push(this.buildItem("Laravel", ["Web frameworks"]));
    if (cookies.includes("PHPSESSID")) techs.push(this.buildItem("PHP", ["Programming languages"]));
    if (cookies.includes("JSESSIONID")) techs.push(this.buildItem("Java", ["Programming languages"]));
    if (cookies.includes("ASP.NET") || cookies.includes("ARRAffinity")) techs.push(this.buildItem("Microsoft ASP.NET / Azure", ["Web frameworks", "PaaS"]));
    
    // Marketing & Tracking
    if (cookies.includes("_hj")) techs.push(this.buildItem("Hotjar", ["Analytics"]));
    if (cookies.includes("_ga")) techs.push(this.buildItem("Google Analytics", ["Analytics"]));
  }

  private detectFromHtml(html: string, techs: TechStackItem[]): void {
    const patterns: Array<{
      regex: RegExp;
      name: string;
      categories: string[];
      version?: RegExp;
    }> = [
      // Frameworks & Bundlers
      { regex: /__next/i, name: "Next.js", categories: ["JavaScript frameworks"], version: /next@([\d.]+)/i },
      { regex: /__nuxt|nuxt\.js/i, name: "Nuxt.js", categories: ["JavaScript frameworks"] },
      { regex: /react(?:\.production|\.development|dom)|_reactInternalInstance/i, name: "React", categories: ["JavaScript frameworks"], version: /react@([\d.]+)/i },
      { regex: /vue(?:\.runtime|\.global|\.esm)|v-cloak|data-v-|__vue_app__/i, name: "Vue.js", categories: ["JavaScript frameworks"], version: /vue@([\d.]+)/i },
      { regex: /angular(?:\.min)?\.js|ng-version|ng-app/i, name: "Angular", categories: ["JavaScript frameworks"], version: /ng-version="([\d.]+)"/i },
      { regex: /vite/i, name: "Vite", categories: ["Build tools"] },
      { regex: /_link_prefetch/i, name: "Qwik", categories: ["JavaScript frameworks"] },
      { regex: /svelte/i, name: "Svelte", categories: ["JavaScript frameworks"] },
      { regex: /gatsby/i, name: "Gatsby", categories: ["JavaScript frameworks"] },
      { regex: /astro/i, name: "Astro", categories: ["JavaScript frameworks"] },
      { regex: /remix/i, name: "Remix", categories: ["JavaScript frameworks"] },
      { regex: /bun\.sh/i, name: "Bun", categories: ["JavaScript runtimes"] },
      { regex: /solid-js/i, name: "Solid.js", categories: ["JavaScript frameworks"] },

      // Libraries & Components
      { regex: /jquery(?:\.min)?\.js|jquery\/([\d.]+)/i, name: "jQuery", categories: ["JavaScript libraries"], version: /jquery[\/\-@]([\d.]+)/i },
      { regex: /lodash|underscore/i, name: "Lodash/Underscore", categories: ["JavaScript libraries"] },
      { regex: /alpine\.?js|x-data|x-on:/i, name: "Alpine.js", categories: ["JavaScript libraries"] },
      { regex: /htmx/i, name: "htmx", categories: ["JavaScript libraries"] },
      { regex: /radix-ui|radix/i, name: "Radix UI", categories: ["UI frameworks"] },
      { regex: /shadcn|cn\(|class-variance-authority/i, name: "Shadcn/UI", categories: ["UI frameworks"] },
      { regex: /lucide/i, name: "Lucide Icons", categories: ["Icon sets"] },
      { regex: /font-awesome|fa-/i, name: "Font Awesome", categories: ["Icon sets"] },
      { regex: /gsap|TweenMax/i, name: "GSAP", categories: ["JavaScript libraries"] },
      { regex: /three\.js|three\.min\.js/i, name: "Three.js", categories: ["JavaScript libraries"] },
      
      // CSS & Styles (Enhanced with class signatures)
      { regex: /tailwindcss|tailwind|tw-|mt-|px-|py-/i, name: "Tailwind CSS", categories: ["UI frameworks"] },
      { regex: /bootstrap(?:\.min)?\.(?:css|js)|row\s+col-|btn- primary/i, name: "Bootstrap", categories: ["UI frameworks"], version: /bootstrap[\/\-@]([\d.]+)/i },
      { regex: /bulma|is-primary|is-flex/i, name: "Bulma", categories: ["UI frameworks"] },
      { regex: /materialize|m-s(\d+)/i, name: "Materialize", categories: ["UI frameworks"] },
      { regex: /chakra-ui|css-[\w]{5,}/i, name: "Chakra UI", categories: ["UI frameworks"] },
      { regex: /styled-components|sc-[\w]{5,}/i, name: "Styled Components", categories: ["Libraries & Languages"] },
      { regex: /emotion|css-[\w]{5,}-/i, name: "Emotion", categories: ["Libraries & Languages"] },

      // CMS & Enterprise Platforms
      { regex: /wp-content|wp-includes|wordpress/i, name: "WordPress", categories: ["CMS"] },
      { regex: /joomla/i, name: "Joomla", categories: ["CMS"] },
      { regex: /drupal\.js|drupal\.settings/i, name: "Drupal", categories: ["CMS"] },
      { regex: /squarespace/i, name: "Squarespace", categories: ["CMS"] },
      { regex: /webflow/i, name: "Webflow", categories: ["CMS"] },
      { regex: /ghost\.io|ghost-/i, name: "Ghost", categories: ["CMS"] },
      { regex: /\/etc\.clientlibs\/|\/content\/dam\//i, name: "Adobe Experience Manager", categories: ["CMS"] },
      { regex: /Sitecore\.Context|scSite/i, name: "Sitecore", categories: ["CMS"] },
      { regex: / Demandware|dw\.js|dwpersonalization/i, name: "Salesforce Commerce Cloud", categories: ["Ecommerce"] },
      { regex: /hubspot/i, name: "HubSpot", categories: ["Marketing automation", "CMS"] },
      
      // Modern Tools
      { regex: /firebase/i, name: "Firebase", categories: ["PaaS"] },
      { regex: /supabase/i, name: "Supabase", categories: ["PaaS"] },
      { regex: /resend/i, name: "Resend", categories: ["Email marketing"] },
      { regex: /posthog/i, name: "PostHog", categories: ["Analytics"] },
      { regex: /sentry/i, name: "Sentry", categories: ["Error tracking"] },

      // Analytics & Marketing
      { regex: /gtag|googletagmanager|google-analytics/i, name: "Google Tag Manager", categories: ["Tag managers"] },
      { regex: /analytics\.js|ga\.js|gtag\/js/i, name: "Google Analytics", categories: ["Analytics"] },
      { regex: /hotjar/i, name: "Hotjar", categories: ["Analytics"] },
      { regex: /intercom/i, name: "Intercom", categories: ["Live chat"] },
      { regex: /crisp\.chat/i, name: "Crisp", categories: ["Live chat"] },
      { regex: /zendesk/i, name: "Zendesk", categories: ["Live chat"] },
      { regex: /segment\.(?:com|io)|analytics\.min\.js/i, name: "Segment", categories: ["Analytics"] },
      { regex: /mixpanel/i, name: "Mixpanel", categories: ["Analytics"] },
      { regex: /plausible/i, name: "Plausible", categories: ["Analytics"] },
      { regex: /clarity\.ms/i, name: "Microsoft Clarity", categories: ["Analytics"] },
      { regex: /fb(?:eventsjs|q\()|facebook\.net\/en_US\/fbevents/i, name: "Facebook Pixel", categories: ["Advertising"] },

      // Ecommerce
      { regex: /shopify/i, name: "Shopify", categories: ["Ecommerce"] },
      { regex: /woocommerce/i, name: "WooCommerce", categories: ["Ecommerce"] },
      { regex: /magento/i, name: "Magento", categories: ["Ecommerce"] },
      { regex: /bigcommerce/i, name: "BigCommerce", categories: ["Ecommerce"] },
      { regex: /stripe/i, name: "Stripe", categories: ["Payment processors"] },

      // Fonts & Miscellaneous
      { regex: /fonts\.googleapis\.com/i, name: "Google Fonts", categories: ["Font scripts"] },
      { regex: /use\.typekit\.net/i, name: "Adobe Fonts", categories: ["Font scripts"] },
      { regex: /Optimizely|optly/i, name: "Optimizely", categories: ["A/B Testing"] },
    ];

    for (const pattern of patterns) {
      if (pattern.regex.test(html)) {
        let version: string | null = null;
        if (pattern.version) {
          const versionMatch = html.match(pattern.version);
          if (versionMatch) version = versionMatch[1];
        }
        const insights = this.getTechInsights(pattern.name, version);
        techs.push({
          name: pattern.name,
          categories: pattern.categories,
          layer: this.mapCategoryToLayer(pattern.categories[0]),
          version,
          isOutdated: this.checkSecurityStatus(pattern.name, version),
          isLegacy: insights.isLegacy,
          impact: insights.impact,
          description: null,
          recommendation: this.getTechRecommendation(
            pattern.name,
            version,
            insights.isLegacy,
            this.checkSecurityStatus(pattern.name, version),
          ),
          confidence: version ? 90 : 70,
          website: null,
          icon: null,
        });
      }
    }

    // Meta generator tag
    const generatorMatch = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i);
    if (generatorMatch) {
      const gen = generatorMatch[1];
      if (!techs.some((t) => gen.toLowerCase().includes(t.name.toLowerCase()))) {
        techs.push(this.buildItem(gen, ["CMS"]));
      }
    }
  }

  public analyzeHealth(
    techs: TechStackItem[],
  ): { modernityScore: number; technicalDebt: string[]; recommendation?: string } {
    if (techs.length === 0) return { modernityScore: 100, technicalDebt: [] };

    let legacyCount = 0;
    const technicalDebt: string[] = [];
    const names = new Set(techs.map((t) => t.name.toLowerCase()));

    if (names.has("jquery") && (names.has("react") || names.has("next.js") || names.has("vue.js"))) {
      technicalDebt.push("Redundant JS Libraries: Site uses both legacy (jQuery) and modern frameworks.");
    }
    if (names.has("bootstrap") && names.has("tailwind css")) {
      technicalDebt.push("Framework Bloat: Multiple UI frameworks (Bootstrap + Tailwind) increase page weight.");
    }
    if (techs.filter((t) => t.layer === "Frontend & UI").length > 3) {
      technicalDebt.push("High JS Overhead: Too many frontend frameworks/libraries detected.");
    }

    for (const tech of techs) {
      if (tech.isLegacy || tech.isOutdated) legacyCount++;
    }

    const modernityScore = Math.max(0, 100 - legacyCount * 15 - technicalDebt.length * 10);

    let recommendation: string | undefined;
    if (modernityScore < 70) {
      const outdated = techs.filter((t) => t.isOutdated).map((t) => t.name);
      const legacy = techs.filter((t) => t.isLegacy).map((t) => t.name);
      const parts: string[] = [];
      if (outdated.length) parts.push("upgrading " + outdated.join(", "));
      if (legacy.length) parts.push("migrating away from " + legacy.join(", "));
      recommendation = "Low Modernity Score: Prioritize " + parts.join(" and ") + ".";
    }

    return { modernityScore, technicalDebt, recommendation };
  }

  private getTechRecommendation(
    name: string,
    version: string | null,
    isLegacy: boolean,
    isOutdated: boolean | null,
  ): string | undefined {
    if (isOutdated) return `Security Risk: Running an outdated version of ${name}. Update to the latest stable release.`;
    if (isLegacy) return `${name} is considered a legacy technology. Explore modern alternatives for better performance.`;
    return undefined;
  }

  private getTechInsights(
    name: string,
    _version: string | null,
  ): { isLegacy: boolean; impact: "low" | "medium" | "high" } {
    const legacyTechs = ["jquery", "bootstrap", "wordpress", "php", "apache http server", "joomla", "magento", "drupal"];
    const highImpactTechs = ["wordpress", "magento", "google tag manager", "hubspot", "hotjar", "intercom"];
    const lowImpactTechs = ["tailwind css", "cloudflare", "next.js", "vite", "alpine.js"];

    const n = name.toLowerCase();
    const isLegacy = legacyTechs.some((l) => n.includes(l));
    let impact: "low" | "medium" | "high" = "medium";

    if (highImpactTechs.some((h) => n.includes(h))) impact = "high";
    else if (lowImpactTechs.some((l) => n.includes(l))) impact = "low";

    return { isLegacy, impact };
  }

  private mapCategoryToLayer(category?: string): string {
    if (!category) return "Miscellaneous";
    const cat = category.toLowerCase();

    if (cat.includes("cms") || cat.includes("ecommerce") || cat.includes("blogs"))
      return "CMS & Platforms";
    if (cat.includes("javascript frameworks") || cat.includes("ui frameworks") || cat.includes("web frameworks"))
      return "Frontend & UI";
    if (cat.includes("web servers") || cat.includes("cdn") || cat.includes("paas") || cat.includes("security"))
      return "Infrastructure & Security";
    if (cat.includes("analytics") || cat.includes("tag managers") || cat.includes("advertising") || cat.includes("marketing") || cat.includes("live chat"))
      return "Analytics & Marketing";
    if (cat.includes("javascript libraries") || cat.includes("programming languages") || cat.includes("font scripts"))
      return "Libraries & Languages";
    if (cat.includes("payment"))
      return "Payment & Commerce";

    return "Other Services";
  }

  private checkSecurityStatus(name: string, version: string | null): boolean | null {
    if (!version) return null;
    
    // Robust version checking: handle semver (e.g., 1.2.3 -> 1.2)
    const normalizedVersion = version.split('.').slice(0, 2).join('.');
    const v = parseFloat(normalizedVersion);
    if (isNaN(v)) return null;

    const outdatedRules: Record<string, number> = {
      jQuery: 3.0,
      WordPress: 6.0,
      PHP: 8.1,
      Bootstrap: 4.0,
      React: 16.0,
      "Next.js": 12.0,
      "Apache HTTP Server": 2.4,
      Nginx: 1.20,
      Angular: 14.0,
      "Vue.js": 3.0,
    };

    const minVersion = outdatedRules[name];
    if (minVersion !== undefined) {
      return v < minVersion;
    }

    return null;
  }

  private buildItem(name: string, categories: string[]): TechStackItem {
    const insights = this.getTechInsights(name, null);
    return {
      name,
      categories,
      layer: this.mapCategoryToLayer(categories[0]),
      version: null,
      isOutdated: null,
      isLegacy: insights.isLegacy,
      impact: insights.impact,
      description: null,
      recommendation: undefined,
      confidence: 50,
      website: null,
      icon: null,
    };
  }
}
