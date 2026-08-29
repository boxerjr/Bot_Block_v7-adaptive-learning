function bytesToB64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/g, "");
}

export async function hashShort(value, length = 24) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(String(value))
  );
  return bytesToB64url(new Uint8Array(digest)).slice(0, length);
}

export function networkBucket(ip) {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(ip || "")) {
    const parts = ip.split(".");
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
  }

  if ((ip || "").includes(":")) {
    return `${ip.split(":").slice(0, 4).join(":")}::/64`;
  }

  return "unknown";
}

function parseNetworks(value) {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.filter(Boolean) : [];
  } catch {
    return [];
  }
}

/**
 * V6.3 fingerprint-reputation compatibility implementation.
 *
 * Behavioral constants intentionally match V6.3:
 * - UA hash length: 16
 * - fingerprint hash length: 32
 * - network-bucket hash length: 14
 * - max remembered networks: 12
 * - state TTL: 1800 seconds
 * - 5 networks => +15 risk
 * - 8 networks => +25 risk
 *
 * M1 stores only hashes and compact stable signals; raw IP and raw UA are not
 * persisted. D1 is used only as shadow compatibility state here.
 */
export async function fingerprintV63Reputation({
  db,
  ip,
  ua,
  network = {},
  telemetry = {},
  nowMs = Date.now(),
}) {
  if (!db) {
    return {
      fpHash: null,
      recentNetworks: 0,
      seen: 0,
      risk: 0,
      reasons: [],
      stored: false,
      reason: "d1_unavailable",
    };
  }

  const stable = {
    ua: await hashShort(ua, 16),
    ja4: network.bot?.ja4 || null,
    platform: telemetry?.navigator?.platform || null,
    vendor: telemetry?.navigator?.vendor || null,
    hc: telemetry?.navigator?.hardwareConcurrency || null,
    dm: telemetry?.navigator?.deviceMemory || null,
    touch: telemetry?.navigator?.maxTouchPoints || null,
    gl: telemetry?.webgl?.renderer || null,
    canvas: telemetry?.canvas || null,
    screen: [
      telemetry?.screen?.width || 0,
      telemetry?.screen?.height || 0,
      telemetry?.screen?.dpr || telemetry?.screen?.pixelRatio || 0,
    ],
    tz: telemetry?.timezone?.name || null,
  };

  const fpHash = await hashShort(JSON.stringify(stable), 32);
  const bucketHash = await hashShort(networkBucket(ip), 14);
  const ttlMs = 1_800_000;

  const row = await db
    .prepare(
      `SELECT network_hashes_json, seen, expires_at_ms
       FROM v63_fingerprint_shadow_state
       WHERE fingerprint_id = ?1`
    )
    .bind(fpHash)
    .first();

  let nets = [];
  let seen = 0;

  if (row && Number(row.expires_at_ms) > nowMs) {
    nets = parseNetworks(row.network_hashes_json);
    seen = Number.isFinite(Number(row.seen)) ? Number(row.seen) : 0;
  }

  if (!nets.includes(bucketHash)) nets.push(bucketHash);
  while (nets.length > 12) nets.shift();
  seen += 1;

  const expiresAtMs = nowMs + ttlMs;

  await db
    .prepare(
      `INSERT INTO v63_fingerprint_shadow_state
         (fingerprint_id, network_hashes_json, seen, last_seen_ms, expires_at_ms)
       VALUES (?1, ?2, ?3, ?4, ?5)
       ON CONFLICT(fingerprint_id) DO UPDATE SET
         network_hashes_json = excluded.network_hashes_json,
         seen = excluded.seen,
         last_seen_ms = excluded.last_seen_ms,
         expires_at_ms = excluded.expires_at_ms`
    )
    .bind(fpHash, JSON.stringify(nets), seen, nowMs, expiresAtMs)
    .run();

  let risk = 0;
  const reasons = [];

  if (nets.length >= 8) {
    risk = 25;
    reasons.push("fingerprint_many_networks");
  } else if (nets.length >= 5) {
    risk = 15;
    reasons.push("fingerprint_multiple_networks");
  }

  return {
    fpHash,
    recentNetworks: nets.length,
    seen,
    risk,
    reasons,
    stored: true,
    expiresAtMs,
  };
}
