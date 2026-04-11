const domain = "grapesworldwide.com";

async function fetchCertFromHackerTarget(domain, ts) {
  const url = `https://api.hackertarget.com/sslcheck/?q=${encodeURIComponent(domain)}&_cb=${ts}&force_refresh=1`;
  try {
    const response = await fetch(url, { 
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36" },
      signal: AbortSignal.timeout(3500) 
    });
    if (!response.ok) return null;
    
    const text = await response.text();
    console.log("HT Response:", text);
    // HackerTarget returns text like "Issuer: CN=WE1, O=Google Trust Services LLC, C=US"
    const issuerMatch = text.match(/Issuer:\s*([^,]+(?:,\s*O=[^,]+)?)/i);
    const expiryMatch = text.match(/Validity End:\s*(.+)/i);
    const startMatch = text.match(/Validity Start:\s*(.+)/i);

    if (!issuerMatch || !expiryMatch) return null;

    let issuerStr = issuerMatch[1].trim();
    // Handle the "WE1, O=Google Trust Services" format
    if (issuerStr.includes("Google Trust Services")) {
      issuerStr = "Google Trust Services (GTS)";
    }
    
    return {
      id: "hackertarget",
      dns_names: [domain],
      issuer: { name: issuerStr, friendly_name: issuerStr.replace("CN=", "").split(",")[0].trim() },
      not_before: startMatch ? startMatch[1].trim() : new Date().toISOString(),
      not_after: expiryMatch[1].trim(),
      cert_sha256: "",
    };
  } catch (err) {
    console.error("HT Error:", err);
    return null;
  }
}

async function fetchCertFromCertSpotter(domain, ts) {
  const url = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=issuer&limit=10&_cb=${ts}`;
  try {
    const response = await fetch(url, {
      signal: AbortSignal.timeout(3500),
      headers: { 
        Accept: "application/json",
        "User-Agent": "Mozilla/5.0"
      },
    });
    if (!response.ok) return null;
    const data = await response.json();
    console.log("CS Response length:", data.length);
    return data[0];
  } catch(err) {
    console.error("CS Error:", err);
    return null;
  }
}

async function run() {
  const ts = Date.now();
  console.log("Running HT...");
  const ht = await fetchCertFromHackerTarget(domain, ts);
  console.log("HT:", ht);
  console.log("Running CS...");
  const cs = await fetchCertFromCertSpotter(domain, ts);
  console.log("CS:", cs ? cs.not_after : null);
}

run();
