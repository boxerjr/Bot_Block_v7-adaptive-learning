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

export async function issueMonitorToken(secret, ttlMs = 90000) {
  const ttl = Math.max(30000, Math.min(180000, Number(ttlMs) || 90000));
  const payload = {
    type: "m22_public_monitor",
    sid: crypto.randomUUID(),
    iat: Date.now(),
    exp: Date.now() + ttl,
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
    if (Date.now() >= Number(payload.exp)) return null;
    return payload;
  } catch {
    return null;
  }
}
