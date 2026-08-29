/*
 * V7 fingerprint module.
 * We intentionally do NOT implement KV read-modify-write reputation here.
 * Persistent reputation will move to D1 / a consistency-safe design.
 */
export function fingerprintVersion() {
  return "v7-fp-1";
}
