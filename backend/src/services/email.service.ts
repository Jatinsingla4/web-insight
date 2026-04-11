export interface EmailAudit {
  spf: {
    isValid: boolean;
    lookupCount: number;
    mechanism: string;
    securityStatus: "secure" | "warning" | "unsafe";
    recommendation?: string;
  };
  dmarc: {
    isFound: boolean;
    policy: string;
    securityStatus: "secure" | "warning" | "unsafe";
    recommendation?: string;
  };
}

export class EmailService {
  public analyzeSpf(spfRecord: string): EmailAudit["spf"] {
    // No SPF record found
    if (!spfRecord || !spfRecord.toLowerCase().startsWith("v=spf1")) {
      return {
        isValid: false,
        lookupCount: 0,
        mechanism: "Not Found",
        securityStatus: "unsafe",
        recommendation: "No SPF record found. Add a TXT record starting with 'v=spf1' to authorize your mail servers and prevent spoofing.",
      };
    }

    const mechanisms = spfRecord.split(/\s+/);
    let lookups = 0;

    // RFC 7208: mechanisms that count toward the 10-lookup limit
    const lookupMechs = ["include", "a", "mx", "ptr", "exists", "redirect"];

    for (const mech of mechanisms) {
      if (lookupMechs.some(m => mech.toLowerCase().startsWith(m))) {
        lookups++;
      }
    }

    const hasStrictFail = spfRecord.includes("-all");
    const hasSoftFail = spfRecord.includes("~all");

    let status: "secure" | "warning" | "unsafe" = "unsafe";
    if (hasStrictFail && lookups <= 10) status = "secure";
    else if (hasSoftFail) status = "warning";
    else if (lookups > 10) status = "warning";

    let recommendation: string | undefined;
    if (!hasStrictFail && !hasSoftFail) {
      recommendation = "SPF record has no enforcement mechanism. Add '-all' (Strict Fail) to reject unauthorized senders.";
    } else if (hasSoftFail) {
      recommendation = "Upgrade SPF from '~all' (Soft Fail) to '-all' (Strict Fail) for stronger protection against spoofing.";
    }
    if (lookups > 10) {
      recommendation = (recommendation ? recommendation + " " : "") +
        `SPF has ${lookups} DNS lookups (RFC limit is 10). Flatten nested includes to ensure reliable delivery.`;
    }

    return {
      isValid: true,
      lookupCount: lookups,
      mechanism: hasStrictFail ? "Strict Fail (-all)" : hasSoftFail ? "Soft Fail (~all)" : "Neutral/None",
      securityStatus: status,
      recommendation,
    };
  }

  public analyzeDmarc(dmarcRecord: string): EmailAudit["dmarc"] {
    // No DMARC record found
    if (!dmarcRecord || !dmarcRecord.toLowerCase().startsWith("v=dmarc1")) {
      return {
        isFound: false,
        policy: "NONE",
        securityStatus: "unsafe",
        recommendation: "No DMARC record found. Add a TXT record at _dmarc.yourdomain.com with 'v=DMARC1; p=reject' to prevent email impersonation.",
      };
    }

    const policyMatch = dmarcRecord.match(/p=([^;\s]+)/i);
    const policy = policyMatch ? policyMatch[1].trim().toLowerCase() : "none";

    let status: "secure" | "warning" | "unsafe" = "unsafe";
    if (policy === "reject") status = "secure";
    else if (policy === "quarantine") status = "warning";

    let recommendation: string | undefined;
    if (policy === "none") {
      recommendation = "DMARC policy is 'p=none' (monitor only). Upgrade to 'p=quarantine' or 'p=reject' to actively block spoofed emails.";
    } else if (policy === "quarantine") {
      recommendation = "DMARC policy is 'p=quarantine'. Consider upgrading to 'p=reject' for maximum protection.";
    }

    return {
      isFound: true,
      policy: policy.toUpperCase(),
      securityStatus: status,
      recommendation,
    };
  }
}
