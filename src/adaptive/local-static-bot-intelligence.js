// Local, vendored bot/scanner intelligence for V7.
//
// Selected declared-bot and scanner names were curated from the MIT-licensed
// Nginx Ultimate Bad Bot Blocker instead of loading that project at runtime:
// https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker
// Upstream list blob: b09f75549695ad1246b2e26855340490909ee8f0
// Upstream release inspected: V4.2026.08.6121 (2026-08-29)
//
// Generic/ambiguous entries and upstream IP/referrer lists are deliberately
// excluded. A static match is detection evidence only: it never creates a
// training label, changes ASN reputation, or stores the raw User-Agent.

export const LOCAL_STATIC_BOT_INTEL_SOURCE = Object.freeze({
  name: "nginx-ultimate-bad-bot-blocker-curated",
  upstreamVersion: "V4.2026.08.6121",
  upstreamListBlob: "b09f75549695ad1246b2e26855340490909ee8f0",
  mode: "vendored_local",
  runtimeExternalDependency: false,
});

// High-confidence tools and automation clients. These are incompatible with
// the public human-browser flow even when HUMANS_ONLY is disabled.
const SCANNER_AUTOMATION_MARKERS = Object.freeze([
  "404checker",
  "404enemy",
  "acunetix",
  "adscanner",
  "aiohttp",
  "burpsuite",
  "censysinspect",
  "cms-security-auditor",
  "curl/",
  "cypress",
  "dirbuster",
  "fhscan",
  "go-http-client",
  "headless",
  "infrasec scanner",
  "jbrofuzz",
  "l9scan",
  "masscan",
  "metasploit",
  "muhstik-scan",
  "nessus",
  "nikto",
  "nmap",
  "node-fetch",
  "openvas",
  "phantomjs",
  "playwright",
  "puppeteer",
  "pycurl",
  "python-requests",
  "scrapy",
  "security team infrasec scanner",
  "selenium",
  "slimerjs",
  "spy4x-domain-scanner",
  "sqlmap",
  "sqlworm",
  "sysscan",
  "tlm-audit-scanner",
  "wget/",
  "wpscan",
]);

// Precise self-declared crawlers/bots. Legitimate crawlers are included
// because V7's HUMANS_ONLY policy intentionally accepts people, not bots.
const DECLARED_BOT_MARKERS = Object.freeze([
  "360spider",
  "adsbot-google",
  "adstxtcrawlertp",
  "ahrefsbot",
  "ai2bot",
  "aihitbot",
  "aipbot",
  "alexibot",
  "aliyunsecbot",
  "alphabot",
  "applebot",
  "archive.org_bot",
  "arquivo-web-crawler",
  "atomseobot",
  "awariobot",
  "awariorssbot",
  "awariosmartbot",
  "baiduspider",
  "barkrowler",
  "bdcbot",
  "bingbot",
  "bingpreview",
  "blexbot",
  "backlinkcrawler",
  "backlinksextendedbot",
  "brandwatch",
  "builtwith",
  "buzzsumo",
  "bytespider",
  "cazoodlebot",
  "ccbot",
  "chatgpt-user",
  "claritybot",
  "claudebot",
  "coccocbot",
  "cocolyzebot",
  "cogentbot",
  "copyscape",
  "crawler4j",
  "crazywebcrawler",
  "crunchbot",
  "dataforseobot",
  "dblbot",
  "demandbase-bot",
  "diibot",
  "discobot",
  "discoverybot",
  "dnbcrawler-analytics",
  "dnyzbot",
  "domcopbot",
  "domaincrawler",
  "domainsigmacrawler",
  "domainstatsbot",
  "dotbot",
  "duckduckbot",
  "erocrawler",
  "exabot",
  "extlinksbot",
  "facebookbot",
  "facebookexternalhit",
  "facebookscraper",
  "femtosearchbot",
  "gptbot",
  "grapeshotcrawler",
  "googlebot",
  "imagesiftbot",
  "indeedbot",
  "istellabot",
  "jikespider",
  "jyxobot",
  "linkdexbot",
  "linkedinbot",
  "lipperhey spider",
  "lmspider",
  "magpie-crawler",
  "mail.ru_bot",
  "majestic seo",
  "majestic-seo",
  "mauibot",
  "meanpath bot",
  "meanpathbot",
  "megaindex.ru",
  "mj12bot",
  "netestate ne crawler",
  "nimblecrawler",
  "orangebot",
  "orangespider",
  "petalbot",
  "quick-crawler",
  "rocketcrawler",
  "semrushbot",
  "seobilitybot",
  "serpstatbot",
  "sogou web spider",
  "sogouspider",
  "timpibot",
  "turnitinbot",
  "twitterbot",
  "uptimerobot",
  "velenpublicwebcrawler",
  "vericitecrawler",
  "vidiblescraper",
  "webmeup-crawler",
  "webprosbot",
  "yandexbot",
  "yandeximages",
  "youdaobot",
  "zitebot",
  "zoombot",
  "zoominfobot",
  "zumbot",
]);

function boolEnv(value, fallback = true) {
  if (value == null || value === "") return fallback;
  return String(value).trim().toLowerCase() === "true";
}

export function localStaticBotIntelEnabled(env = {}) {
  return boolEnv(env.LOCAL_STATIC_BOT_INTEL_ENABLED, true);
}

export function classifyLocalStaticUa(
  uaValue,
  { humansOnly = true } = {}
) {
  const ua = String(uaValue || "").trim().toLowerCase();
  if (!ua) {
    return {
      matched: false,
      tier: "none",
      category: null,
      marker: null,
      source: "v7_local_curated",
    };
  }

  const scannerMarker = SCANNER_AUTOMATION_MARKERS.find((marker) =>
    ua.includes(marker)
  );
  if (scannerMarker) {
    return {
      matched: true,
      tier: "hard",
      category: "scanner_or_automation",
      marker: scannerMarker,
      source: "v7_local_curated",
    };
  }

  if (humansOnly) {
    const declaredMarker = DECLARED_BOT_MARKERS.find((marker) =>
      ua.includes(marker)
    );
    if (declaredMarker) {
      return {
        matched: true,
        tier: "hard",
        category: "declared_bot_or_crawler",
        marker: declaredMarker,
        source: "v7_local_curated",
      };
    }
  }

  return {
    matched: false,
    tier: "none",
    category: null,
    marker: null,
    source: "v7_local_curated",
  };
}

export function localStaticBotIntelStats() {
  return {
    scannerAutomationMarkers: SCANNER_AUTOMATION_MARKERS.length,
    declaredBotMarkers: DECLARED_BOT_MARKERS.length,
    totalMarkers:
      SCANNER_AUTOMATION_MARKERS.length + DECLARED_BOT_MARKERS.length,
    upstreamVersion: LOCAL_STATIC_BOT_INTEL_SOURCE.upstreamVersion,
    upstreamListBlob: LOCAL_STATIC_BOT_INTEL_SOURCE.upstreamListBlob,
    mode: LOCAL_STATIC_BOT_INTEL_SOURCE.mode,
    runtimeExternalDependency:
      LOCAL_STATIC_BOT_INTEL_SOURCE.runtimeExternalDependency,
  };
}

