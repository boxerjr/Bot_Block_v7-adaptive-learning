export const SYNTHETIC_LEARNING_ASN = "AS64512";

export function hostileLearningFixture() {
  const ua =
    "Mozilla/5.0 (Linux; Android 14; V7 Synthetic Device) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36";

  return {
    scope: "test",
    datasetEligible: false,
    synthetic: true,
    network: {
      country: "ZZ",
      asn: SYNTHETIC_LEARNING_ASN,
      org: "V7 synthetic private-use network",
    },
    ua,
    telemetry: {
      navigator: {
        platform: "Linux armv8l",
        vendor: "Google Inc.",
        hardwareConcurrency: 8,
        deviceMemory: 8,
        maxTouchPoints: 5,
      },
      webgl: {
        renderer: "V7 Synthetic Mobile GPU",
      },
      screen: {
        width: 412,
        height: 915,
        pixelRatio: 2.625,
      },
      timezone: {
        name: "Europe/Madrid",
      },
    },
    // Deliberately near the adaptive review boundary but still a V6.3 allow
    // fixture. This endpoint tests learning mechanics, not V6.3 compatibility.
    v63Decision: "allow",
    v63DecisionStage: "post_ai",
    baseRisk: 45,
  };
}
