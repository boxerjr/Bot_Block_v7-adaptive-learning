function bytesToB64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/g, "");
}

async function importHmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(String(secret)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

function stableBrowserMaterial(ua, telemetry = {}) {
  const nav = telemetry.navigator || {};
  const screen = telemetry.screen || {};
  const webgl = telemetry.webgl || {};
  const timezone = telemetry.timezone || {};

  return {
    v: 1,
    ua: String(ua || ""),
    platform: nav.platform || null,
    vendor: nav.vendor || null,
    hardwareConcurrency: Number(nav.hardwareConcurrency || 0),
    deviceMemory: Number(nav.deviceMemory || 0),
    maxTouchPoints: Number(nav.maxTouchPoints || 0),
    webglRenderer: webgl.renderer || null,
    screen: [
      Number(screen.width || 0),
      Number(screen.height || 0),
      Number(screen.pixelRatio || screen.dpr || 0),
    ],
    timezone: timezone.name || null,
    canvas: telemetry.canvas || null,
  };
}

/**
 * Produces an installation-keyed, pseudonymous fingerprint identifier.
 * Raw UA/browser material is used only as HMAC input and is never returned.
 * No IP or network bucket participates in the identifier.
 */
export async function deriveAdaptiveFingerprintId(secret, { ua = "", telemetry = {} } = {}) {
  if (!secret) return null;

  const material = JSON.stringify(stableBrowserMaterial(ua, telemetry));
  const key = await importHmacKey(secret);
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(material)
  );

  return `v7fp_${bytesToB64url(new Uint8Array(signature)).slice(0, 32)}`;
}
