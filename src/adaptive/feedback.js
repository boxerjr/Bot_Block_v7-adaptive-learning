const ALLOWED_LABELS = new Set(["human", "bot", "spoof", "uncertain"]);

export function normalizeFeedbackLabel(value) {
  const label = String(value || "").trim().toLowerCase();
  return ALLOWED_LABELS.has(label) ? label : null;
}
