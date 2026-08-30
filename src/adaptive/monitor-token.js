function bytesToB64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/g, "");
}

function b64urlToBytes(value) {
  let input = String(value || "").replaceAll("-", "+").replaceAll("_", "/");
  while (input.length % 4) input += "=";
  const binary = atob(input);
  const output = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) output[i] = binary.charCodeAt(i);
  return output;
}

function textToB64url(text) {
  return bytesToB64url(new TextEncoder().encode(String(text)));
}

function b64urlToText(value) {
  return new TextDecoder().decode(b64urlToBytes(value));
}

async function hmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(String(secret)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function signText(secret, body) {
  const key = await hmacKey(secret);
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(body)
  );
  return bytesToB64url(new Uint8Array(signature));
}

function safeEqual(a, b) {
  const aa = String(a || "");
  const bb = String(b || "");
  if (aa.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < aa.length; i++) diff |= aa.charCodeAt(i) ^ bb.charCodeAt(i);
  return diff === 0;
}

function validIpKey(value) {
  return /^m22ip_[A-Za-z0-9_-]{32}$/.test(String(value || ""));
}

async function monitorIpBinding(secret, sid, ipKey) {
  if (!secret || !sid || !validIpKey(ipKey)) return null;
  return (await signText(secret, `m22-monitor-ip-binding:${sid}:${ipKey}`)).slice(0, 32);
}

/**
 * ipKey is optional only for backwards-compatible lower-layer tests.
 * The production V7 release-hardening entrypoint always supplies an exact-IP
 * HMAC and rejects unbound tokens before they can reach the monitor engine.
 */
export async function issueMonitorToken(secret, ttlMs = 90000, ipKey = null) {
  const ttl = Math.max(30000, Math.min(180000, Number(ttlMs) || 90000));
  const now = Date.now();
  const sid = crypto.randomUUID();
  const payload = {
    type: "m22_public_monitor",
    sid,
    iat: now,
    exp: now + ttl,
    ipb: validIpKey(ipKey) ? await monitorIpBinding(secret, sid, ipKey) : null,
  };
  const body = textToB64url(JSON.stringify(payload));
  return {
    token: `${body}.${await signText(secret, body)}`,
    payload,
  };
}

export async function verifyMonitorToken(secret, token) {
  try {
    if (!secret) return null;
    const [body, signature, extra] = String(token || "").split(".");
    if (!body || !signature || extra) return null;

    const key = await hmacKey(secret);
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      b64urlToBytes(signature),
      new TextEncoder().encode(body)
    );
    if (!valid) return null;

    const payload = JSON.parse(b64urlToText(body));
    if (payload?.type !== "m22_public_monitor") return null;
    if (!payload.sid || !Number.isFinite(Number(payload.exp))) return null;
    if (payload.ipb != null && !/^[A-Za-z0-9_-]{32}$/.test(String(payload.ipb))) return null;
    if (Date.now() >= Number(payload.exp)) return null;
    return payload;
  } catch {
    return null;
  }
}

export async function monitorTokenMatchesIpKey(secret, payload, ipKey) {
  try {
    if (!secret || !payload?.sid || !validIpKey(ipKey)) return false;
    if (!/^[A-Za-z0-9_-]{32}$/.test(String(payload.ipb || ""))) return false;
    const expected = await monitorIpBinding(secret, payload.sid, ipKey);
    return safeEqual(payload.ipb, expected);
  } catch {
    return false;
  }
}
