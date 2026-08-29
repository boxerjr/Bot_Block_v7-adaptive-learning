function bool(value) {
  return value === true;
}

function bucketNumber(value, thresholds) {
  const n = Number(value || 0);
  for (const [max, label] of thresholds) {
    if (n <= max) return label;
  }
  return thresholds.at(-1)?.[1] || "unknown";
}

function platformFamily(ua = "", platform = "") {
  const value = `${ua} ${platform}`.toLowerCase();
  if (/iphone|ipad|ipod|ios/.test(value)) return "ios";
  if (/android/.test(value)) return "android";
  if (/windows|win32|win64/.test(value)) return "windows";
  if (/macintosh|macintel|mac os/.test(value)) return "macos";
  if (/linux/.test(value)) return "linux";
  return "other";
}

function vendorFamily(value = "") {
  const text = String(value || "").toLowerCase();
  if (/apple/.test(text)) return "apple";
  if (/google/.test(text)) return "google";
  if (/qualcomm|adreno/.test(text)) return "qualcomm";
  if (/nvidia/.test(text)) return "nvidia";
  if (/amd|radeon/.test(text)) return "amd";
  if (/intel/.test(text)) return "intel";
  if (/arm|mali/.test(text)) return "arm";
  return text ? "other" : "unknown";
}

function screenClass(screen = {}) {
  const width = Math.max(0, Number(screen.width || 0));
  const height = Math.max(0, Number(screen.height || 0));
  const short = Math.min(width, height);
  const long = Math.max(width, height);

  if (!short || !long) return "unknown";
  if (short <= 430 && long <= 1000) return "phone";
  if (short <= 900 && long <= 1400) return "tablet";
  return "large";
}

function interactionBucket(value) {
  const n = Math.max(0, Number(value || 0));
  if (n === 0) return "0";
  if (n <= 3) return "1-3";
  if (n <= 10) return "4-10";
  return "11+";
}

function ratioBucket(value) {
  const n = Math.max(0, Math.min(1, Number(value ?? 0)));
  if (n < 0.25) return "low";
  if (n < 0.75) return "medium";
  return "high";
}

export function sanitizeLiveFeatureSummary({ ua = "", telemetry = {} } = {}) {
  const nav = telemetry.navigator || {};
  const media = telemetry.media || {};
  const webgl = telemetry.webgl || {};
  const automation = telemetry.automation || {};
  const capabilities = telemetry.capabilities || {};
  const interaction = telemetry.interaction || {};
  const screen = telemetry.screen || {};

  const automationDetected = [
    nav.webdriver,
    automation.selenium,
    automation.phantom,
    automation.nightmare,
    automation.webdriverAttr,
    automation.cdc,
  ].some(bool);

  return {
    schema_version: 1,
    device: {
      platform_family: platformFamily(ua, nav.platform),
      navigator_vendor_family: vendorFamily(nav.vendor),
      touch_points_bucket: bucketNumber(nav.maxTouchPoints, [
        [0, "0"],
        [2, "1-2"],
        [5, "3-5"],
        [1000, "6+"],
      ]),
      hardware_concurrency_bucket: bucketNumber(nav.hardwareConcurrency, [
        [2, "1-2"],
        [4, "3-4"],
        [8, "5-8"],
        [16, "9-16"],
        [1000, "17+"],
      ]),
      device_memory_bucket: bucketNumber(nav.deviceMemory, [
        [0, "unknown"],
        [2, "1-2"],
        [4, "3-4"],
        [8, "5-8"],
        [1000, "9+"],
      ]),
      screen_class: screenClass(screen),
      pixel_ratio_bucket: bucketNumber(screen.pixelRatio || screen.dpr, [
        [1, "<=1"],
        [2, "1-2"],
        [3, "2-3"],
        [1000, ">3"],
      ]),
    },
    pointer: {
      fine: bool(media.pointerFine),
      coarse: bool(media.pointerCoarse),
      hover: bool(media.anyHoverHover),
    },
    gpu: {
      vendor_family: vendorFamily(`${webgl.vendor || ""} ${webgl.renderer || ""}`),
    },
    automation: {
      detected: automationDetected,
    },
    capabilities: {
      serial: bool(capabilities.serial),
      usb: bool(capabilities.usb),
      hid: bool(capabilities.hid),
      bluetooth: bool(capabilities.bluetooth),
      screen_details: bool(capabilities.getScreenDetails),
      file_system_access: bool(capabilities.fileSystemAccess),
    },
    interaction: {
      total_bucket: interactionBucket(interaction.total),
      trusted_ratio_bucket: ratioBucket(interaction.trustedRatio),
      touch_present: Number(interaction.touch || 0) > 0,
      mouse_present: Number(interaction.mouse || 0) > 0,
      key_present: Number(interaction.key || 0) > 0,
    },
  };
}

export function buildLiveLabelRecord({
  eventId,
  label,
  confidence,
  createdAt = new Date().toISOString(),
} = {}) {
  return {
    schema_version: 1,
    event_id: String(eventId || ""),
    label: String(label || ""),
    confidence: Math.max(0, Math.min(100, Number(confidence || 0))),
    source: "manual_admin",
    scope: "live",
    training_eligible: true,
    created_at: createdAt,
    raw_ip_stored: false,
    user_agent_stored: false,
    raw_telemetry_stored: false,
  };
}
