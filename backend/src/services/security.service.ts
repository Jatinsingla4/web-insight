export interface SecurityHeaderAudit {
  name: string;
  status: "secure" | "warning" | "missing";
  value: string | null;
  description: string;
  recommendation?: string;
}

export interface CookieAudit {
  name: string;
  isHttpOnly: boolean;
  isSecure: boolean;
  sameSite: string | null;
  recommendation?: string;
}

export class SecurityService {
  async analyzeHeaders(url: string): Promise<{ headers: SecurityHeaderAudit[]; score: number; cookies: CookieAudit[]; isHstsPreloadReady: boolean }> {
    try {
      const response = await fetch(url, {
        method: "GET",
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 DNSChecker/1.0",
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        },
        redirect: "follow",
        signal: AbortSignal.timeout(6000),
      });

      const headers = response.headers;
      const audit: SecurityHeaderAudit[] = [];
      let score = 100;

      // 1. Content-Security-Policy
      const csp = headers.get("content-security-policy");
      if (csp) {
        audit.push({
          name: "Content-Security-Policy",
          status: "secure",
          value: this.truncateHeader(csp),
          description: "Restricts sources for scripts and styles to prevent XSS attacks.",
        });
      } else {
        score -= 25;
        audit.push({
          name: "Content-Security-Policy",
          status: "missing",
          value: null,
          description: "Critical! Missing CSP makes the site vulnerable to injection attacks.",
          recommendation: "Implement a strict CSP. Example: Content-Security-Policy: default-src 'self'; script-src 'self' https://scripts.example.com;",
        });
      }

      // 2. Strict-Transport-Security
      const hsts = headers.get("strict-transport-security");
      if (hsts) {
        audit.push({
          name: "Strict-Transport-Security",
          status: "secure",
          value: hsts,
          description: "Forces browsers to use HTTPS for all future communication.",
        });
      } else {
        score -= 20;
        audit.push({
          name: "Strict-Transport-Security",
          status: "missing",
          value: null,
          description: "Vulnerable to SSL stripping attacks. HTTPS is not strictly enforced.",
          recommendation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to your server headers.",
        });
      }

      // 3. X-Frame-Options
      const xfo = headers.get("x-frame-options");
      if (xfo && (xfo.toUpperCase() === "DENY" || xfo.toUpperCase() === "SAMEORIGIN")) {
        audit.push({
          name: "X-Frame-Options",
          status: "secure",
          value: xfo,
          description: "Prevents the site from being embedded in frames, stopping Clickjacking.",
        });
      } else {
        score -= 15;
        audit.push({
          name: "X-Frame-Options",
          status: xfo ? "warning" : "missing",
          value: xfo,
          description: "Clickjacking risk! Site can potentially be embedded by unauthorized domains.",
          recommendation: "Enforce 'X-Frame-Options: SAMEORIGIN' to prevent your site from being framed maliciously.",
        });
      }

      // 4. X-Content-Type-Options
      const xcto = headers.get("x-content-type-options");
      if (xcto && xcto.toLowerCase() === "nosniff") {
        audit.push({
          name: "X-Content-Type-Options",
          status: "secure",
          value: xcto,
          description: "Tells the browser not to 'guess' the MIME type of a response.",
        });
      } else {
        score -= 10;
        audit.push({
          name: "X-Content-Type-Options",
          status: "missing",
          value: null,
          description: "MIME-sniffing risk! Vulnerable to some drive-by-download attacks.",
          recommendation: "Set 'X-Content-Type-Options: nosniff' to disable MIME-type sniffing.",
        });
      }

      // 5. Referrer-Policy
      const ref = headers.get("referrer-policy");
      if (ref) {
        audit.push({
          name: "Referrer-Policy",
          status: "secure",
          value: ref,
          description: "Controls what information is sent in the Referer header.",
        });
      } else {
        score -= 10;
        audit.push({
          name: "Referrer-Policy",
          status: "warning",
          value: null,
          description: "Privacy risk! Referer header might leak sensitive internal URLs.",
          recommendation: "Set 'Referrer-Policy: strict-origin-when-cross-origin' to protect user privacy while maintaining analytics.",
        });
      }

      // 6. Permissions-Policy
      const permissions = headers.get("permissions-policy");
      let isHstsPreloadReady = false;
      if (hsts) {
        const hstsLower = hsts.toLowerCase();
        const hasSubdomains = hstsLower.includes("includesubdomains");
        const hasPreload = hstsLower.includes("preload");
        const maxAgeMatch = hstsLower.match(/max-age=(\d+)/);
        const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]) : 0;
        isHstsPreloadReady = hasSubdomains && hasPreload && maxAge >= 31536000;
      }

      if (permissions) {
        audit.push({
          name: "Permissions-Policy",
          status: "secure",
          value: this.truncateHeader(permissions),
          description: "Defines which browser features (camera, mic) are allowed.",
        });
      } else {
        score -= 5;
        audit.push({
          name: "Permissions-Policy",
          status: "missing",
          value: null,
          description: "Browser features are not explicitly restricted.",
          recommendation: "Add a Permissions-Policy header to disable unused features (e.g., 'camera=(), microphone=()').",
        });
      }

      return {
        headers: audit,
        score: Math.max(0, score),
        cookies: this.analyzeCookies(headers),
        isHstsPreloadReady,
      };
    } catch {
      return { headers: [], score: 0, cookies: [], isHstsPreloadReady: false };
    }
  }

  private analyzeCookies(headers: Headers): CookieAudit[] {
    const cookies: CookieAudit[] = [];
    const setCookie = headers.get("set-cookie");
    if (!setCookie) return [];

    // Cloudflare Worker Headers.get() for set-cookie returns all values concatenated with commas
    // but parsing them accurately is tricky if the cookie value itself contains commas (rare but possible).
    // For standard audit purposes, we split by common separators.
    const parts = setCookie.split(/,(?=[^;]+?=)/); 

    for (const cookieStr of parts) {
      const attributes = cookieStr.split(";").map(s => s.trim());
      const nameValue = attributes[0].split("=");
      const name = nameValue[0];
      
      const isHttpOnly = attributes.some(s => s.toLowerCase() === "httponly");
      const isSecure = attributes.some(s => s.toLowerCase() === "secure");
      const sameSiteAttr = attributes.find(s => s.toLowerCase().startsWith("samesite="));
      const sameSite = sameSiteAttr ? sameSiteAttr.split("=")[1] : null;

      const recommendations: string[] = [];
      if (!isHttpOnly) recommendations.push("Set 'HttpOnly' flag to prevent XSS access.");
      if (!isSecure) recommendations.push("Set 'Secure' flag to ensure HTTPS-only transmission.");
      if (!sameSite) recommendations.push("Set 'SameSite=Lax' to mitigate CSRF attacks.");

      cookies.push({
        name,
        isHttpOnly,
        isSecure,
        sameSite,
        recommendation: recommendations.length > 0 ? recommendations.join(" ") : undefined,
      });
    }

    return cookies;
  }

  private truncateHeader(value: string): string {
    return value.length > 100 ? value.substring(0, 97) + "..." : value;
  }
}
