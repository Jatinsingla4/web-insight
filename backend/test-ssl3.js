const domain = "grapesworldwide.com";

async function fetchCertFromHackerTarget(domain) {
  const url = `https://api.hackertarget.com/sslcheck/?q=${encodeURIComponent(domain)}`;
  try {
    const response = await fetch(url, { 
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36" },
      signal: AbortSignal.timeout(3500) 
    });
    console.log("HT response status:", response.status);
    const text = await response.text();
    console.log("HT text:", text);
  } catch (err) {
    console.error("error:", err)
  }
}

fetchCertFromHackerTarget(domain);
