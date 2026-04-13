import type { DnsRecord } from "@dns-checker/shared";
import { DNS_RECORD_TYPES, CACHE_TTL_SECONDS } from "@dns-checker/shared";

interface GoogleDnsAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

interface GoogleDnsResponse {
  Status: number;
  Answer?: GoogleDnsAnswer[];
  Authority?: GoogleDnsAnswer[];
  AD?: boolean;
}

const DNS_TYPE_MAP: Record<number, string> = {
  1: "A",
  2: "NS",
  5: "CNAME",
  6: "SOA",
  15: "MX",
  16: "TXT",
  28: "AAAA",
  33: "SRV",
  257: "CAA",
};

const DNS_TYPE_NUM: Record<string, number> = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  CAA: 257,
};

/** DNS resolvers with automatic fallback */
const DNS_RESOLVERS = [
  { name: "Google", url: "https://dns.google/resolve" },
  { name: "Cloudflare", url: "https://cloudflare-dns.com/dns-query" },
  { name: "NextDNS", url: "https://dns.nextdns.io/resolve" },
  { name: "Alibaba DNS", url: "https://dns.alidns.com/resolve" },
  { name: "OpenDNS", url: "https://doh.opendns.com/dns-query" },
] as const;

const BIMI_SELECTORS = ["default", "corporate", "promo", "mail"];

export class DnsService {
  constructor(private readonly cache: KVNamespace) {}

  /**
   * Quick A record resolution — used by scan orchestrator to get IP
   * before launching all parallel services. Fast, single query.
   */
  async quickResolveA(domain: string): Promise<string | null> {
    const aRecord = await this.queryDns(domain, "A").then((res) => res.records.find(r => r.type === "A"));
    return aRecord?.data ?? null;
  }

  async checkCaa(domain: string): Promise<boolean> {
    try {
      // Query CAA (Type 257)
      const res = await this.queryDns(domain, "CAA");
      if (res.records.length > 0) return true;

      // Check apex if subdomain
      const apex = this.getApexDomain(domain);
      if (domain !== apex) {
        const apexRes = await this.queryDns(apex, "CAA");
        return apexRes.records.length > 0;
      }
      return false;
    } catch {
      return false;
    }
  }

  async checkTlsa(domain: string): Promise<boolean> {
    try {
      // TLSA is prefixed with port and protocol: _443._tcp.domain.com
      const tlsaDomain = `_443._tcp.${domain}`;
      const res = await this.queryDns(tlsaDomain, "TLSA");
      return res.records.length > 0;
    } catch {
      return false;
    }
  }

  async checkHttpsRecords(domain: string): Promise<{ h3: boolean; quic: boolean }> {
    try {
      const res = await this.queryDns(domain, "HTTPS");
      const hasH3 = res.records.some(r => r.data.includes("h3") || r.data.includes("h2"));
      return { h3: hasH3, quic: hasH3 };
    } catch {
      return { h3: false, quic: false };
    }
  }

  async lookup(domain: string, force = false): Promise<{
    records: DnsRecord[];
    nameservers: string[];
    whois?: any;
    consensus?: any;
    audit: any;
  }> {
    const cacheKey = `dns:v3:${domain}`;
    if (!force) {
      const cached = await this.cache.get<any>(cacheKey, "json");
      if (cached) return cached;
    }

    const apexDomain = this.getApexDomain(domain);
    
    // Deep Probing: Parallel queries for Internal, Apex, DMARC, BIMI-Discovery, DNSSEC-DS, WHOIS, and Consensus
    const [
      rootRecords, 
      apexRecords, 
      dmarcResponse, 
      bimiDiscovery, 
      dsProbing,
      externalRecords,
      whoisData,
      consensusData
    ] = await Promise.all([
      this.fetchAllRecords(domain),
      domain !== apexDomain ? this.fetchAllRecords(apexDomain) : Promise.resolve({ records: [], dnssec: false }),
      this.queryDns(`_dmarc.${domain}`, "TXT").then(async (res) => {
        if (res.records.length === 0 && domain !== apexDomain) {
          return this.queryDns(`_dmarc.${apexDomain}`, "TXT");
        }
        return res;
      }),
      this.discoverBimi(domain, apexDomain),
      this.queryDns(domain, "DS"), // Direct DS-record probing (Ground Truth)
      this.queryExternalFallback(domain),
      this.lookupWhois(apexDomain),
      this.runConsensusCheck(domain),
    ]);

    // Merge and deduplicate records
    const allRecords = [
      ...rootRecords.records,
      ...apexRecords.records,
      ...dmarcResponse.records,
      ...bimiDiscovery,
      ...externalRecords,
      ...dsProbing.records,
    ];

    const uniqueRecordsMap = new Map();
    allRecords.forEach(r => {
      const normalizedName = r.name.replace(/\.$/, "");
      const normalizedData = r.type === "TXT" ? this.cleanTxtRecord(r.data) : r.data;
      const key = `${r.type}:${normalizedName}:${normalizedData}`;
      if (!uniqueRecordsMap.has(key)) {
        uniqueRecordsMap.set(key, { ...r, name: normalizedName, data: normalizedData });
      }
    });

    const records = Array.from(uniqueRecordsMap.values());
    
    // DNSSEC Consensus: Check AD flag OR existence of DS records
    const dnssecEnabled = rootRecords.dnssec || apexRecords.dnssec || dsProbing.records.length > 0;
    
    const spfRecord = records.find(r => r.type === "TXT" && r.data.toLowerCase().includes("v=spf1"));
    const dmarcRecord = records.find(r => r.type === "TXT" && r.data.toLowerCase().includes("v=dmarc1"));
    const bimiRecord = records.find(r => r.type === "TXT" && r.data.toLowerCase().includes("v=bimi1"));

    const audit = {
      spfStatus: spfRecord?.data ?? null,
      dmarcStatus: dmarcRecord?.data ?? null,
      dnssecEnabled,
      bimiRecordPresent: !!bimiRecord,
      isEmailSecure: !!(spfRecord && dmarcRecord),
      recommendations: this.generateRecommendations(records, dnssecEnabled),
    };

    const result = { 
      records, 
      nameservers: records.filter(r => r.type === "NS").map(r => r.data), 
      whois: whoisData,
      consensus: consensusData,
      audit 
    };

    await this.cache.put(cacheKey, JSON.stringify(result), {
      expirationTtl: CACHE_TTL_SECONDS,
    });

    return result;
  }

  /** Fetch registration and expiry data via RDAP */
  private async lookupWhois(domain: string): Promise<any> {
    try {
      const url = `https://rdap.org/domain/${encodeURIComponent(domain)}`;
      const response = await fetch(url, {
        headers: { "Accept": "application/rdap+json" },
        signal: AbortSignal.timeout(5000),
      });

      if (!response.ok) return null;
      const data = await response.json() as any;

      const events = data.events || [];
      const createdEvent = events.find((e: any) => e.eventAction === "registration");
      const expiryEvent = events.find((e: any) => e.eventAction === "expiration");

      const createdDate = createdEvent ? createdEvent.eventDate : null;
      const expiryDate = expiryEvent ? expiryEvent.eventDate : null;
      
      let isExpiringSoon = false;
      if (expiryDate) {
        const daysLeft = Math.ceil((new Date(expiryDate).getTime() - Date.now()) / (1000 * 60 * 60 * 24));
        isExpiringSoon = daysLeft < 30;
      }

      return {
        registrar: data.entities?.[0]?.vcardArray?.[1]?.find((v: any) => v[0] === "fn")?.[3] || "Unknown",
        createdDate,
        expiryDate,
        isExpiringSoon,
      };
    } catch {
      return null;
    }
  }

  /** Compare A and MX records across multiple resolvers to detect hijacking */
  private async runConsensusCheck(domain: string): Promise<any> {
    const resolvers = DNS_RESOLVERS.slice(0, 3); // Google, Cloudflare, NextDNS
    const checks = resolvers.map(r => this.queryResolver(r.url, domain, 1)); // Type A = 1
    
    try {
      const settled = await Promise.allSettled(checks);
      const results: string[][] = [];
      const warnings: string[] = [];

      settled.forEach((res, i) => {
        if (res.status === "fulfilled") {
          results.push(res.value.records.map(r => r.data).sort());
        } else {
          warnings.push(`Resolver ${resolvers[i].name} failed.`);
        }
      });

      if (results.length < 2) return { isConsistent: true, resolversChecked: resolvers.map(r => r.name), warnings };

      const first = JSON.stringify(results[0]);
      const inconsistent = results.some(r => JSON.stringify(r) !== first);

      if (inconsistent) {
        warnings.push("CRITICAL: DNS Resolution inconsistency detected across different global providers! Potential DNS hijacking or poisoning.");
      }

      return {
        isConsistent: !inconsistent,
        resolversChecked: resolvers.map(r => r.name),
        warnings,
      };
    } catch {
      return { isConsistent: true, resolversChecked: [], warnings: [] };
    }
  }

  private async discoverBimi(domain: string, apexDomain: string): Promise<DnsRecord[]> {
    const records: DnsRecord[] = [];
    const domainsToCheck = domain === apexDomain ? [domain] : [domain, apexDomain];
    
    for (const d of domainsToCheck) {
      const bimiQueries = BIMI_SELECTORS.map(selector => 
        this.queryDns(`${selector}._bimi.${d}`, "TXT")
      );
      const results = await Promise.allSettled(bimiQueries);
      results.forEach(res => {
        if (res.status === "fulfilled") {
          records.push(...res.value.records);
        }
      });
      if (records.length > 0) break;
    }
    return records;
  }

  private async queryExternalFallback(domain: string): Promise<DnsRecord[]> {
    try {
      const response = await fetch(`https://api.hackertarget.com/dnslookup/?q=${encodeURIComponent(domain)}`, {
        headers: { "User-Agent": "DNS-Checker-FullProof/1.0" },
        signal: AbortSignal.timeout(6000),
      });

      if (!response.ok) return [];
      const text = await response.text();
      return this.parseHackerTargetResponse(text);
    } catch (err) {
      console.error("External DNS Fallback Failed:", err);
      return [];
    }
  }

  private parseHackerTargetResponse(text: string): DnsRecord[] {
    const records: DnsRecord[] = [];
    const lines = text.split('\n');
    
    for (const line of lines) {
      // Format: domain.com. TYPE DATA
      // Example: google.com. TXT "v=spf1 ..."
      const match = line.match(/^([^\s]+)\s+([A-Z0-9]+)\s+(.+)$/);
      if (match) {
        records.push({
          name: match[1].replace(/\.$/, ""),
          type: match[2],
          data: match[3],
        });
      }
    }
    return records;
  }

  public getApexDomain(domain: string): string {
    const parts = domain.split('.');
    if (parts.length <= 2) return domain;
    // Simple apex detection: last two parts (e.g., google.com from www.google.com)
    // Note: This doesn't handle co.uk etc. perfectly, but handles 99% of business domains.
    return parts.slice(-2).join('.');
  }

  private cleanTxtRecord(data: string): string {
    // Standardize multi-part TXT records and remove quotes
    return data
      .replace(/^"|"$/g, '')
      .replace(/"\s+"/g, '')
      .trim();
  }

  private async fetchAllRecords(domain: string): Promise<{ records: DnsRecord[], dnssec: boolean }> {
    const results = await Promise.allSettled(
      DNS_RECORD_TYPES.map(type => this.queryDns(domain, type))
    );

    const records: DnsRecord[] = [];
    let dnssec = false;

    results.forEach(res => {
      if (res.status === "fulfilled") {
        records.push(...res.value.records);
        if (res.value.dnssec) dnssec = true;
      }
    });

    return { records, dnssec };
  }

  private async queryDns(domain: string, type: string): Promise<{ records: DnsRecord[], dnssec: boolean }> {
    const typeNum = DNS_TYPE_NUM[type as keyof typeof DNS_TYPE_NUM] || 1;
    
    for (const resolver of DNS_RESOLVERS) {
      try {
        const response = await this.queryResolver(resolver.url, domain, typeNum);
        if (response.records.length > 0 || response.dnssec) {
          return response;
        }
      } catch (err) {
        // Silently skip intermittent failures (400, 429, 503, JSON Syntax Errors)
        const errorMessage = String(err);
        // Silently skip: 400 (Bad Request), 401/403 (Policy Block/Unauthorized), 429 (Rate Limit), SyntaxError (JSON)
        const isPolicyBlock = errorMessage.includes("401") || errorMessage.includes("403");
        const isClientError = errorMessage.includes("400") || errorMessage.includes("SyntaxError");
        
        if (!isPolicyBlock && !isClientError) {
          console.error(`DNS Warning for ${domain} (${type}) on ${resolver.name}:`, err);
        }
        continue;
      }
    }

    return { records: [], dnssec: false };
  }

  private async queryResolver(resolverUrl: string, domain: string, typeNum: number): Promise<{ records: DnsRecord[], dnssec: boolean }> {
    const url = `${resolverUrl}?name=${encodeURIComponent(domain)}&type=${typeNum}&do=true`;
    
    const response = await fetch(url, {
      headers: { 
        "Accept": "application/dns-json",
        "User-Agent": "DNS-Checker-Hardened/1.0"
      },
      signal: AbortSignal.timeout(8000), // Increased timeout to 8s
    });

    if (!response.ok) {
      throw new Error(`DNS Resolver returned ${response.status}`);
    }

    try {
      const data = await response.json() as any;
      
      if (!data.Answer) {
        return { records: [], dnssec: data.AD ?? false };
      }

      const records = data.Answer.map((answer: any) => ({
        type: DNS_TYPE_MAP[answer.type] || `TYPE${answer.type}`,
        name: answer.name.replace(/\.$/, ""),
        data: answer.data,
        ttl: answer.TTL,
      }));

      return { records, dnssec: data.AD ?? false };
    } catch (err) {
      throw new Error(`Invalid JSON response from ${resolverUrl}: ${String(err)}`);
    }
  }

  private generateRecommendations(records: DnsRecord[], dnssecEnabled: boolean): string[] {
    const recommendations: string[] = [];
    
    if (!dnssecEnabled) {
      recommendations.push("Enable DNSSEC to prevent DNS spoofing and cache poisoning attacks.");
    }

    const hasSpf = records.some(r => r.type === "TXT" && r.data.toLowerCase().includes("v=spf1"));
    if (!hasSpf) {
      recommendations.push("Missing SPF record. Add an SPF TXT record to authorize your mail servers.");
    }

    const hasDmarc = records.some(r => r.type === "TXT" && r.data.toLowerCase().includes("v=dmarc1"));
    if (!hasDmarc) {
      recommendations.push("Missing DMARC record. Implement a DMARC policy to protect your brand from email spoofing.");
    }

    return recommendations;
  }

  async checkReputation(ip: string): Promise<boolean | null> {
    if (!ip || !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) return null;
    const reversedIp = ip.split(".").reverse().join(".");
    
    // Multi-source reputation check (Spamhaus, Barracuda, SORBS)
    const lists = [
      `${reversedIp}.zen.spamhaus.org`,
      `${reversedIp}.b.barracudacentral.org`,
      `${reversedIp}.dnsbl.sorbs.net`
    ];

    try {
      // Strict 4s timeout for reputation to prevent hanging
      const timeoutPromise = new Promise<null>((_, reject) => 
        setTimeout(() => reject(new Error("Timeout")), 4000)
      );

      return await Promise.race([
        (async () => {
          const results = await Promise.allSettled(
            lists.map(list => this.queryDns(list, "A"))
          );

          return results.some(res => 
            res.status === "fulfilled" && 
            res.value.records.length > 0 &&
            res.value.records.some(r => 
              r.data.startsWith("127.0.0.") && 
              !r.data.endsWith(".10") && // PBL
              !r.data.endsWith(".11")    // PBL
            )
          );
        })(),
        timeoutPromise
      ]);
    } catch {
      return null;
    }
  }

  private generateDnsRecommendations(data: {
    hasSpf: boolean;
    hasDmarc: boolean;
    dnssecEnabled: boolean;
    hasBimi: boolean;
  }): string[] {
    const recs: string[] = [];
    if (!data.hasSpf) recs.push("Missing SPF: Add a TXT record (v=spf1 ...) to authorize your mail servers.");
    if (!data.hasDmarc) recs.push("Missing DMARC: Implement a 'p=quarantine' or 'p=reject' policy to prevent spoofing.");
    if (!data.dnssecEnabled) recs.push("DNSSEC Disabled: Enable DNSSEC at your registrar to prevent DNS hijacking/poisoning.");
    if (!data.hasBimi) recs.push("BIMI Missing: Configure a BIMI record to display your brand logo in email clients.");
    return recs;
  }
}
