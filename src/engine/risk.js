export function clamp(value, min = 0, max = 100) {
  return Math.max(min, Math.min(max, Number(value) || 0));
}

export function addRisk(state, points, reason, { critical = false, spoof = false } = {}) {
  state.risk += points;
  if (!state.reasons.includes(reason)) state.reasons.push(reason);
  if (critical) state.critical = true;
  if (spoof) state.spoofSignals++;
  return state;
}
