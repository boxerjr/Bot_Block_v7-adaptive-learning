export function boolEnv(value, fallback = false) {
  if (value == null || value === "") return fallback;
  return String(value).toLowerCase() === "true";
}

export function intEnv(value, fallback, min = 0, max = 1_000_000_000) {
  const n = Number.parseInt(String(value ?? ""), 10);
  return Number.isFinite(n) ? Math.max(min, Math.min(max, n)) : fallback;
}

export function csvSet(value, fallback = "") {
  return new Set(
    String(value || fallback)
      .split(",")
      .map((x) => x.trim().toUpperCase())
      .filter(Boolean)
  );
}
