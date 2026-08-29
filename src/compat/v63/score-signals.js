import { HARD_ASNS, RISK_ASNS, SAFE_ASNS, STRONG_BOT_UA } from "./policy.js";

function boolEnv(value, fallback = false) {
  if (value == null || value === "") return fallback;
  return String(value).toLowerCase() === "true";
}

function clamp(value, min = 0, max = 100) {
  return Math.max(min, Math.min(max, Number(value) || 0));
}

function uaClaim(ua) {
  ua = String(ua || "");

  const ios = /(iphone|ipad|ipod)/i.test(ua);
  const android = /android/i.test(ua);
  const mobile = ios || android || /mobile/i.test(ua);
  const safari =
    /safari/i.test(ua) &&
    !/(crios|fxios|edgios|opios|chrome|chromium)/i.test(ua);

  return { ios, android, mobile, safari };
}

function addRisk(state, points, reason, { critical = false, spoof = false } = {}) {
  state.risk += points;

  if (!state.reasons.includes(reason)) {
    state.reasons.push(reason);
  }

  if (critical) state.critical = true;
  if (spoof) state.spoofSignals++;
}

function desktopPlatform(value = "") {
  return /(win32|win64|windows|macintel|linux x86|x86_64|amd64)/i.test(
    String(value)
  );
}

function desktopGpu(renderer = "", vendor = "") {
  return /(nvidia|geforce|quadro|radeon\s+(rx|pro)|amd\s+radeon|intel\(r\)|intel iris|intel uhd|intel hd graphics|apple m[1-9]|swiftshader|llvmpipe|vmware|virtualbox|parallels)/i.test(
    `${renderer} ${vendor}`
  );
}

/**
 * Function-for-function compatibility port of V6.3 scoreSignals().
 * Shadow-only: it computes the V6.3 local result but performs no enforcement.
 */
export function scoreV63Signals({ request, env = {}, network = {}, ua = "", telemetry = {} }) {
  const state = {
    risk: 0,
    reasons: [],
    critical: false,
    spoofSignals: 0,
    strongHardwareSpoof: false,
  };

  const claim = uaClaim(ua);
  const nav = telemetry?.navigator || {};
  const uaData = telemetry?.uaData || {};
  const win = telemetry?.window || {};
  const media = telemetry?.media || {};
  const webgl = telemetry?.webgl || {};
  const webgpu = telemetry?.webgpu || {};
  const capabilities = telemetry?.capabilities || {};
  const fonts = Array.isArray(telemetry?.fonts) ? telemetry.fonts : [];
  const automation = telemetry?.automation || {};
  const performanceData = telemetry?.performance || {};
  const asn = network.asn;

  // ASN
  if (asn && HARD_ASNS.has(asn) && !SAFE_ASNS.has(asn)) {
    addRisk(state, 100, "hard_cloud_asn", { critical: true });
  } else if (asn && RISK_ASNS.has(asn) && !SAFE_ASNS.has(asn)) {
    addRisk(state, 30, "risk_asn");
  }

  if (asn && SAFE_ASNS.has(asn)) {
    state.risk -= 5;
    state.reasons.push("safe_access_asn");
  }

  // Cloudflare Bot Management
  const bot = network.bot;

  if (bot?.verifiedBot && boolEnv(env.HUMANS_ONLY, true)) {
    addRisk(state, 100, "cf_verified_bot", { critical: true });
  }

  if (typeof bot?.score === "number") {
    if (bot.score <= 5) {
      addRisk(state, 70, "cf_bot_score_1_5");
    } else if (bot.score <= 10) {
      addRisk(state, 55, "cf_bot_score_6_10");
    } else if (bot.score <= 29) {
      addRisk(state, 30, "cf_bot_score_11_29");
    } else if (bot.score >= 80) {
      state.risk -= 8;
      state.reasons.push("cf_bot_score_high");
    }
  }

  if (bot?.jsDetectionPassed === false) {
    addRisk(state, 12, "cf_js_detection_not_passed");
  }

  if (bot?.jsDetectionPassed === true) {
    state.risk -= 5;
    state.reasons.push("cf_js_detection_passed");
  }

  // Automation
  const botUa = STRONG_BOT_UA.find((marker) =>
    String(ua).toLowerCase().includes(marker)
  );

  if (botUa) {
    addRisk(state, 100, `automation_ua:${botUa}`, { critical: true });
  }

  if (nav.webdriver === true) {
    addRisk(state, 100, "navigator_webdriver_true", { critical: true });
  }

  if (
    automation.selenium ||
    automation.phantom ||
    automation.nightmare ||
    automation.webdriverAttr ||
    automation.cdc
  ) {
    addRisk(state, 95, "automation_global", { critical: true });
  }

  if (nav.userAgent && String(nav.userAgent) !== String(ua)) {
    addRisk(state, 70, "http_js_ua_mismatch", { spoof: true });
  }

  // Mobile claim
  if (claim.mobile) {
    if (Number(nav.maxTouchPoints) === 0) {
      addRisk(state, 45, "mobile_zero_touch", { spoof: true });
    }

    if (media.pointerFine === true && media.pointerCoarse !== true) {
      addRisk(state, 30, "mobile_fine_pointer", { spoof: true });
    }

    if (media.anyHoverHover === true) {
      addRisk(state, 25, "mobile_hover", { spoof: true });
    }

    const ipadMacIntel =
      claim.ios &&
      /ipad/i.test(ua) &&
      /macintel/i.test(String(nav.platform || ""));

    if (desktopPlatform(nav.platform) && !ipadMacIntel) {
      addRisk(state, 45, "mobile_desktop_platform", { spoof: true });
    }

    const webglLooksDesktop = desktopGpu(webgl.renderer, webgl.vendor);

    if (webglLooksDesktop) {
      addRisk(state, 50, "mobile_desktop_webgl", { spoof: true });
    }

    const webgpuLooksDesktop = desktopGpu(
      webgpu.description,
      `${webgpu.vendor || ""} ${webgpu.architecture || ""}`
    );

    if (webgpuLooksDesktop) {
      addRisk(state, 50, "mobile_desktop_webgpu", { spoof: true });
    }

    if (/(x86|x64|amd64)/i.test(String(uaData.architecture || ""))) {
      addRisk(state, 45, "mobile_x86_architecture", { spoof: true });
    }

    // V6.3: high CPU count on a claimed phone is a spoof signal.
    const highCpu = Number(nav.hardwareConcurrency) > 16;

    if (highCpu) {
      addRisk(state, 15, "mobile_high_cpu", { spoof: true });
    }

    // V6.3 correlated hardware rules.
    if (webglLooksDesktop && highCpu) {
      addRisk(state, 25, "desktop_gpu_plus_high_cpu_mobile_claim", {
        spoof: true,
      });
      state.strongHardwareSpoof = true;
    }

    if (webglLooksDesktop && webgpuLooksDesktop) {
      addRisk(state, 20, "dual_desktop_gpu_evidence", { spoof: true });
      state.strongHardwareSpoof = true;
    }

    if (desktopPlatform(nav.platform) && webglLooksDesktop && !ipadMacIntel) {
      addRisk(state, 20, "desktop_platform_plus_gpu_mobile_claim", {
        spoof: true,
      });
      state.strongHardwareSpoof = true;
    }
  }

  // iOS Safari
  if (claim.ios && claim.safari) {
    if (nav.vendor && !/apple/i.test(String(nav.vendor))) {
      addRisk(state, 55, "ios_safari_non_apple_vendor", { spoof: true });
    }

    const platform = String(nav.platform || "");
    const platformOk = /ipad/i.test(ua)
      ? /(ipad|macintel)/i.test(platform)
      : /(iphone|ipod)/i.test(platform);

    if (platform && !platformOk) {
      addRisk(state, 50, "ios_safari_impossible_platform", { spoof: true });
    }

    if (win.chromePresent === true) {
      addRisk(state, 50, "ios_safari_window_chrome", { spoof: true });
    }

    if (uaData.present === true) {
      addRisk(state, 50, "ios_safari_user_agent_data", { spoof: true });
    }

    if (performanceData.memoryPresent === true) {
      addRisk(state, 30, "ios_safari_performance_memory", { spoof: true });
    }

    if (Number(nav.deviceMemory) > 0) {
      addRisk(state, 30, "ios_safari_device_memory", { spoof: true });
    }

    if (
      capabilities.serial ||
      capabilities.usb ||
      capabilities.hid ||
      capabilities.getScreenDetails ||
      capabilities.fileSystemAccess
    ) {
      addRisk(state, 25, "ios_safari_chromium_desktop_api", { spoof: true });
    }

    const windowsFonts = fonts.filter((font) =>
      ["Segoe UI", "Calibri", "Consolas", "Cambria"].includes(font)
    ).length;

    if (windowsFonts >= 2) {
      addRisk(state, 30, "ios_safari_windows_fonts", { spoof: true });
    }
  }

  // Android
  if (claim.android) {
    if (uaData.present === true && uaData.mobile === false) {
      addRisk(state, 50, "android_uadata_mobile_false", { spoof: true });
    }

    if (desktopPlatform(nav.platform)) {
      addRisk(state, 50, "android_desktop_platform", { spoof: true });
    }
  }

  // Client hints
  const chPlatform = request?.headers?.get?.("sec-ch-ua-platform") ?? null;
  const chMobile = request?.headers?.get?.("sec-ch-ua-mobile") ?? null;

  if (claim.android && chPlatform && !/android/i.test(chPlatform)) {
    addRisk(state, 45, "android_ch_platform_mismatch", { spoof: true });
  }

  if (claim.mobile && chMobile === "?0") {
    addRisk(state, 45, "mobile_ch_mobile_false", { spoof: true });
  }

  if (uaData.present && claim.mobile && uaData.mobile === false) {
    addRisk(state, 45, "mobile_high_entropy_false", { spoof: true });
  }

  // Passive events
  if (
    (telemetry?.interaction?.total || 0) > 0 &&
    Number(telemetry?.interaction?.trustedRatio) < 0.5
  ) {
    addRisk(state, 35, "untrusted_passive_events");
  }

  // Multiple spoof contradictions
  if (state.spoofSignals >= 3) {
    addRisk(state, 30, "multiple_spoof_contradictions");
  }

  if (state.spoofSignals >= 5) {
    addRisk(state, 20, "many_spoof_contradictions");
  }

  // V6.3 strong hardware floor.
  if (state.strongHardwareSpoof && state.risk < 75) {
    state.risk = 75;

    if (!state.reasons.includes("strong_hardware_spoof_floor")) {
      state.reasons.push("strong_hardware_spoof_floor");
    }
  }

  state.risk = clamp(state.risk);
  return state;
}
