import { browserProbeHtml } from "../compat/v63/browser-probe.js";

export function monitorBrowserProbeHtml(token) {
  return browserProbeHtml(token)
    .replaceAll("V7 M1 Browser Probe", "V7 Public Traffic Monitor")
    .replaceAll(
      "/_shadow/browser-probe-submit",
      "/_shadow/v7-monitor-submit"
    )
    .replaceAll(
      "Probe complete. This remains shadow-only and is excluded from training.",
      "Traffic check complete. Shadow result sent to Telegram; excluded from training."
    )
    .replaceAll(
      "Collecting real browser telemetry in shadow mode…",
      "Checking traffic in V6.3 + V7 shadow mode…"
    );
}
