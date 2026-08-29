import { browserProbeHtml } from "../compat/v63/browser-probe.js";

export function liveBrowserProbeHtml(token) {
  return browserProbeHtml(token)
    .replaceAll("V7 M1 Browser Probe", "V7 M2.1 Live Shadow Probe")
    .replaceAll(
      "/_shadow/browser-probe-submit",
      "/_shadow/v7-live-submit"
    )
    .replaceAll(
      "Probe complete. This remains shadow-only and is excluded from training.",
      "Live shadow capture complete. This is dataset-eligible but remains non-enforcing."
    );
}
