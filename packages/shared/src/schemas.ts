import { z } from "zod";

// ── URL validation ──────────────────────────────────────────────────────────
export const urlSchema = z
  .string()
  .min(1, "URL is required")
  .transform((val) => {
    if (!val.startsWith("http://") && !val.startsWith("https://")) {
      return `https://${val}`;
    }
    return val;
  })
  .pipe(z.string().url("Invalid URL format"));

export const domainSchema = z
  .string()
  .min(1, "Domain is required")
  .transform((val) => {
    let clean = val.trim().toLowerCase();
    // Remove protocol if present
    clean = clean.replace(/^https?:\/\//, "");
    // Remove path and query params
    clean = clean.split("/")[0];
    return clean;
  })
  .refine(
    (val) => /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(val),
    "Invalid domain format",
  );

// ── Quick Scan ──────────────────────────────────────────────────────────────
export const quickScanInputSchema = z.object({
  url: urlSchema,
  force: z.boolean().optional(),
});

export const techStackItemSchema = z.object({
  name: z.string(),
  categories: z.array(z.string()),
  layer: z.string().optional(),
  version: z.string().nullable(),
  isOutdated: z.boolean().nullable(),
  isLegacy: z.boolean().optional(),
  impact: z.enum(["low", "medium", "high"]).optional(),
  description: z.string().nullable(),
  recommendation: z.string().optional(),
  confidence: z.number().min(0).max(100),
  website: z.string().nullable(),
  icon: z.string().nullable(),
});

export const dnsRecordSchema = z.object({
  type: z.string(),
  name: z.string(),
  data: z.string(),
  ttl: z.number().optional(),
  recommendation: z.string().optional(),
});

export const sslCertificateSchema = z.object({
  subject: z.string(),
  issuer: z.string(),
  validFrom: z.string(),
  validTo: z.string(),
  daysUntilExpiry: z.number().nullable(),
  grade: z.string().nullable(),
  protocol: z.string().nullable(),
  keyAlgorithm: z.string().nullable(),
  keySize: z.number().nullable(),
  signatureAlgorithm: z.string().nullable(),
  hstsEnabled: z.boolean().nullable(),
  isVulnerable: z.boolean().nullable(),
  forwardSecrecy: z.boolean().nullable(),
  ocspStapling: z.boolean().nullable(),
  alpnSupported: z.boolean().nullable(),
  tls13Enabled: z.boolean().nullable(),
  tls12Enabled: z.boolean().nullable(),
  ctCompliant: z.boolean().nullable(),
  caaRecordPresent: z.boolean().nullable(),
  // Direct TCP extraction fields
  cipherSuiteName: z.string().nullable().optional(),
  chainLength: z.number().nullable().optional(),
  sctCount: z.number().nullable().optional(),
  isSelfSigned: z.boolean().nullable().optional(),
  deepScanStatus: z.enum(["pending", "scanning", "ready", "failed"]).optional(),
  scannedAt: z.string().optional(),
  recommendation: z.string().optional(),
});

export const scanResultSchema = z.object({
  url: z.string(),
  domain: z.string(),
  scannedAt: z.string(),
  techStack: z.array(techStackItemSchema),
  dns: z.object({
    records: z.array(dnsRecordSchema),
    nameservers: z.array(z.string()),
    whois: z.object({
      registrar: z.string().nullable(),
      createdDate: z.string().nullable(),
      expiryDate: z.string().nullable(),
      isExpiringSoon: z.boolean().nullable(),
    }).optional(),
    consensus: z.object({
      isConsistent: z.boolean(),
      resolversChecked: z.array(z.string()),
      warnings: z.array(z.string()),
    }).optional(),
    audit: z.object({
      spfStatus: z.string().nullable(),
      dmarcStatus: z.string().nullable(),
      dnssecEnabled: z.boolean().nullable(),
      bimiRecordPresent: z.boolean().nullable(),
      isEmailSecure: z.boolean(),
      recommendations: z.array(z.string()).optional(),
    }).optional(),
  }),
  ssl: sslCertificateSchema.extend({
    ocspStapling: z.boolean().nullable().optional(),
    ctCompliant: z.boolean().nullable().optional(),
    ctLogsCount: z.number().nullable().optional(),
  }).nullable(),
  server: z.object({
    ip: z.string().nullable(),
    location: z.object({
      country: z.string(),
      countryCode: z.string(),
      city: z.string(),
      isp: z.string(),
      org: z.string(),
      as: z.string(),
      provider: z.string().optional(),
      latencyMs: z.number().optional(),
      dataCenter: z.string().optional(),
    }).nullable(),
    blacklisted: z.boolean().nullable(),
  }).optional(),
  security: z.object({
    headers: z.array(z.object({
      name: z.string(),
      status: z.enum(["secure", "warning", "missing"]),
      value: z.string().nullable(),
      description: z.string(),
      recommendation: z.string().optional(),
    })),
    score: z.number(),
  }).optional(),
  techStackHealth: z.object({
    modernityScore: z.number(),
    technicalDebt: z.array(z.string()),
    recommendation: z.string().optional(),
  }).optional(),
  vulnerabilityExposure: z.array(z.object({
    path: z.string(),
    status: z.enum(["exposed", "secure", "unknown"]),
    description: z.string(),
    solution: z.string().optional(),
  })).optional(),
  cookieAudit: z.array(z.object({
    name: z.string(),
    isHttpOnly: z.boolean(),
    isSecure: z.boolean(),
    sameSite: z.string().nullable(),
    recommendation: z.string().optional(),
  })).optional(),
  trustAudit: z.object({
    externalScripts: z.array(z.object({
      url: z.string(),
      domain: z.string(),
      hasSri: z.boolean(),
    })),
    uniqueDomainsCount: z.number(),
    sriComplianceScore: z.number(),
  }).optional(),
  connectivity: z.object({
    redirectChain: z.array(z.string()),
    isHstsPreloadReady: z.boolean(),
    wwwRedirectStatus: z.enum(["success", "warning", "error"]),
    socialLinks: z.array(z.object({
      platform: z.string(),
      url: z.string(),
      isSecure: z.boolean(),
    })),
  }).optional(),
  emailSecurity: z.object({
    spf: z.object({
      isValid: z.boolean(),
      lookupCount: z.number(),
      mechanism: z.string(),
      securityStatus: z.enum(["secure", "warning", "unsafe"]),
      recommendation: z.string().optional(),
    }),
    dmarc: z.object({
      isFound: z.boolean(),
      policy: z.string(),
      securityStatus: z.enum(["secure", "warning", "unsafe"]),
      recommendation: z.string().optional(),
    }),
  }).optional(),
  privacyAudit: z.object({
    trackingPixels: z.array(z.string()),
    hasPrivacyPolicy: z.boolean(),
    hasTermsOfService: z.boolean(),
    policyAnalysis: z.object({
      verified: z.boolean(),
      containsGdprLinks: z.boolean(),
      containsCcpaLinks: z.boolean(),
      lastCheckedAt: z.string().optional(),
    }).optional(),
  }).optional(),
});

// ── Brand Management ────────────────────────────────────────────────────────
export const createBrandSchema = z.object({
  domain: domainSchema,
  name: z.string().min(1).max(100),
  initialScanData: scanResultSchema.optional(),
});

export const updateBrandSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1).max(100).optional(),
  domain: domainSchema.optional(),
});

export const sslReminderInputSchema = z.object({
  domain: z.string().min(1).max(255),
  expiryDate: z.string(),
  notifyEmails: z.array(z.string().email("Invalid email format")).default([]),
  thresholdDays: z.array(z.number().min(1).max(365)).default([30, 7, 1]),
  isEnabled: z.boolean().default(true),
});

export type SslReminderInput = z.infer<typeof sslReminderInputSchema>;

export const brandIdSchema = z.object({
  id: z.string().uuid(),
});

// ── Rescan ──────────────────────────────────────────────────────────────────
export const rescanInputSchema = z.object({
  brandId: z.string().uuid(),
});

// ── Pagination ──────────────────────────────────────────────────────────────
export const paginationSchema = z.object({
  cursor: z.string().optional(),
  limit: z.number().min(1).max(100).default(20),
});

export const scanHistoryInputSchema = z.object({
  brandId: z.string().uuid(),
  cursor: z.string().optional(),
  limit: z.number().min(1).max(50).default(20),
});
 
export const compareScansSchema = z.object({
  brandId: z.string().uuid(),
  currentScanId: z.string().uuid().optional(),
  previousScanId: z.string().uuid().optional(),
});

export const sslStatusInputSchema = z.object({
  domain: domainSchema,
});
