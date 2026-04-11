export interface IpLocation {
  status: string;
  country: string;
  countryCode: string;
  city: string;
  isp: string;
  org: string;
  as: string;
  query: string;
  provider?: string;
  latencyMs?: number;
  dataCenter?: string;
}

const IATA_MAP: Record<string, string> = {
  BOM: "Mumbai, India",
  DEL: "Delhi, India",
  BLR: "Bangalore, India",
  MAA: "Chennai, India",
  HYD: "Hyderabad, India",
  CCU: "Kolkata, India",
  SIN: "Singapore",
  DXB: "Dubai, UAE",
  LHR: "London, UK",
  FRA: "Frankfurt, Germany",
  AMS: "Amsterdam, Netherlands",
  CDG: "Paris, France",
  JFK: "New York, USA",
  SFO: "San Francisco, USA",
  LAX: "Los Angeles, USA",
  NRT: "Tokyo, Japan",
  HKG: "Hong Kong",
};

export class IpService {
  constructor(private readonly cache: KVNamespace) {}

  async analyze(ip: string, headers?: Headers, force = false): Promise<IpLocation | null> {
    const cacheKey = `ip:${ip}`;
    if (!force) {
      const cached = await this.cache.get<IpLocation>(cacheKey, "json");
      if (cached) return cached;
    }

    const start = Date.now();
    // Try primary (ip-api.com — highly accurate for Anycast/Regional nodes)
    // Then fallbacks: ipapi.co, ipwho.is
    const result = await this.fetchFromIpApiCom(ip) ?? 
                   await this.fetchFromIpApiCo(ip) ?? 
                   await this.fetchFromIpWhois(ip);
    const latencyMs = Date.now() - start;

    if (result) {
      result.latencyMs = latencyMs;
      result.provider = this.identifyProvider(result.isp, result.as);
      
      // Transit Intelligence: Force hardware-level location if headers exist
      if (headers) {
        const transit = this.identifyTransitLocation(headers);
        if (transit) {
          result.city = transit.city;
          result.country = transit.country;
          result.dataCenter = transit.code;
        }
      }
      
      await this.cache.put(cacheKey, JSON.stringify(result), {
        expirationTtl: 86400 * 7, // 1 week cache
      });
    }

    return result;
  }

  private identifyProvider(isp: string, as: string): string | undefined {
    const raw = `${isp} ${as}`.toLowerCase();
    
    if (raw.includes("amazon") || raw.includes("aws")) return "Amazon Web Services (AWS)";
    if (raw.includes("google cloud") || raw.includes("google llc")) return "Google Cloud Platform (GCP)";
    if (raw.includes("cloudflare")) return "Cloudflare Infrastructure";
    if (raw.includes("vercel")) return "Vercel Platform";
    if (raw.includes("digitalocean")) return "DigitalOcean";
    if (raw.includes("linode")) return "Akamai (Linode)";
    if (raw.includes("fastly")) return "Fastly Edge";
    if (raw.includes("github")) return "GitHub Infrastructure";
    if (raw.includes("microsoft") || raw.includes("azure")) return "Microsoft Azure";
    if (raw.includes("hetzner")) return "Hetzner Online";
    if (raw.includes("ovh")) return "OVHcloud";
    
    return undefined;
  }

  private identifyTransitLocation(headers: Headers): { city: string; country: string; code: string } | null {
    // Cloudflare: CF-Ray (e.g., "7a123-BOM")
    const cfRay = headers.get("cf-ray");
    if (cfRay && cfRay.includes("-")) {
      const code = cfRay.split("-").pop()?.toUpperCase();
      if (code && IATA_MAP[code]) {
        const [city, country] = IATA_MAP[code].split(", ");
        return { city, country: country || "Unknown", code };
      }
    }

    // AWS CloudFront: X-Amz-Cf-Pop (e.g., "BOM50-C1")
    const cfPop = headers.get("x-amz-cf-pop");
    if (cfPop) {
      const code = cfPop.slice(0, 3).toUpperCase();
      if (IATA_MAP[code]) {
        const [city, country] = IATA_MAP[code].split(", ");
        return { city, country: country || "Unknown", code };
      }
    }

    // Fastly / Vercel: X-Served-By
    const servedBy = headers.get("x-served-by");
    if (servedBy && servedBy.includes("-")) {
      const code = servedBy.split("-").pop()?.toUpperCase().slice(0, 3);
      if (code && IATA_MAP[code]) {
        const [city, country] = IATA_MAP[code].split(", ");
        return { city, country: country || "Unknown", code };
      }
    }

    return null;
  }

  private async fetchFromIpApiCom(ip: string): Promise<IpLocation | null> {
    try {
      const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,query`, {
        signal: AbortSignal.timeout(5000),
      });

      if (!response.ok) return null;

      const data = (await response.json()) as any;
      if (data.status !== "success") return null;

      return {
        status: "success",
        country: data.country ?? "",
        countryCode: data.countryCode ?? "",
        city: data.city ?? "",
        isp: data.isp ?? "",
        org: data.org ?? "",
        as: data.as ?? "",
        query: ip,
      };
    } catch {
      return null;
    }
  }

  /** Primary: ipapi.co — HTTPS, free tier 1000 req/day, no auth */
  private async fetchFromIpApiCo(ip: string): Promise<IpLocation | null> {
    try {
      const response = await fetch(`https://ipapi.co/${ip}/json/`, {
        signal: AbortSignal.timeout(5000),
      });

      if (!response.ok) return null;

      const data = (await response.json()) as any;
      if (data.error) return null;

      return {
        status: "success",
        country: data.country_name ?? "",
        countryCode: data.country_code ?? "",
        city: data.city ?? "",
        isp: data.org ?? "",
        org: data.org ?? "",
        as: data.asn ? `AS${data.asn}` : "",
        query: ip,
      };
    } catch {
      return null;
    }
  }

  /** Fallback: ipwho.is — HTTPS, free, no rate limit, no auth */
  private async fetchFromIpWhois(ip: string): Promise<IpLocation | null> {
    try {
      const response = await fetch(`https://ipwho.is/${ip}`, {
        signal: AbortSignal.timeout(5000),
      });

      if (!response.ok) return null;

      const data = (await response.json()) as any;
      if (!data.success) return null;

      return {
        status: "success",
        country: data.country ?? "",
        countryCode: data.country_code ?? "",
        city: data.city ?? "",
        isp: data.connection?.isp ?? "",
        org: data.connection?.org ?? "",
        as: data.connection?.asn ? `AS${data.connection.asn}` : "",
        query: ip,
      };
    } catch {
      return null;
    }
  }
}
