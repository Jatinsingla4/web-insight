export class EmailService {
  /**
   * Analyze an SPF record for security best practices.
   */
  analyzeSpf(record: string) {
    const isFound = !!record && record.toLowerCase().startsWith("v=spf1");
    if (!isFound) {
      return {
        isValid: false,
        lookupCount: 0,
        mechanism: "none",
        securityStatus: "unsafe" as const,
        recommendation: "Missing SPF record. This allows anyone to spoof emails from your domain.",
      };
    }

    // Simplified logic for SPF analysis
    const hasAll = record.includes("-all") || record.includes("~all");
    const isHardFail = record.includes("-all");
    
    // Heuristic for lookup count (just for demonstration)
    const lookupCount = (record.match(/include:|a:|mx:/g) || []).length;

    let securityStatus: "secure" | "warning" | "unsafe" = "warning";
    let recommendation = "";

    if (isHardFail && lookupCount <= 10) {
      securityStatus = "secure";
    } else if (lookupCount > 10) {
      securityStatus = "unsafe";
      recommendation = "SPF record has too many lookups (>10). Some recipients may reject your emails.";
    } else if (!isHardFail) {
      recommendation = "SPF record uses soft-fail (~all). Consider switching to hard-fail (-all) for better security.";
    }

    return {
      isValid: true,
      lookupCount,
      mechanism: isHardFail ? "Hard Fail" : "Soft Fail",
      securityStatus,
      recommendation: recommendation || "SPF record is correctly configured.",
    };
  }

  /**
   * Analyze a DMARC record for security policy strength.
   */
  analyzeDmarc(record: string) {
    const isFound = !!record && record.toLowerCase().startsWith("v=dmarc1");
    if (!isFound) {
      return {
        isFound: false,
        policy: "none",
        securityStatus: "unsafe" as const,
        recommendation: "Missing DMARC record. Email spoofing protection is not enforced.",
      };
    }

    const policyMatch = record.match(/p=([^;]+)/i);
    const policy = policyMatch ? policyMatch[1].toLowerCase() : "none";

    let securityStatus: "secure" | "warning" | "unsafe" = "warning";
    let recommendation = "";

    if (policy === "reject") {
      securityStatus = "secure";
      recommendation = "DMARC policy is set to 'reject', providing maximum protection.";
    } else if (policy === "quarantine") {
      securityStatus = "warning";
      recommendation = "DMARC policy is set to 'quarantine'. Consider moving to 'reject' once traffic is verified.";
    } else {
      securityStatus = "unsafe";
      recommendation = "DMARC policy is set to 'none' (monitoring only). Spoofing is not being blocked.";
    }

    return {
      isFound: true,
      policy: policy.toUpperCase(),
      securityStatus,
      recommendation,
    };
  }
}
