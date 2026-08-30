export function clientIp(request) {
  // Cloudflare sets CF-Connecting-IP at the edge. Do not fall back to
  // X-Forwarded-For for enforcement identity because that header can be
  // client-controlled in non-standard/proxied request paths.
  const value = request?.headers?.get?.("cf-connecting-ip") || "";
  return String(value).trim() || "unknown";
}

export function networkInfo(request) {
  const cf = request.cf || {};
  const bm = cf.botManagement || null;

  return {
    country: cf.country || request.headers.get("cf-ipcountry") || null,
    asn: Number.isFinite(cf.asn) ? `AS${cf.asn}` : null,
    org: cf.asOrganization || null,
    httpProtocol: cf.httpProtocol || null,
    tlsVersion: cf.tlsVersion || null,
    colo: cf.colo || null,
    rtt: Number.isFinite(cf.clientTcpRtt) ? cf.clientTcpRtt : null,
    bot: bm
      ? {
          score: typeof bm.score === "number" ? bm.score : null,
          verifiedBot: !!bm.verifiedBot,
          staticResource: !!bm.staticResource,
          ja3Hash: bm.ja3Hash || null,
          ja4: bm.ja4 || null,
          jsDetectionPassed:
            typeof bm.jsDetection?.passed === "boolean"
              ? bm.jsDetection.passed
              : null,
          detectionIds: Array.isArray(bm.detectionIds)
            ? bm.detectionIds.slice(0, 20)
            : [],
        }
      : null,
  };
}
