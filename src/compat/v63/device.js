export function uaClaim(ua) {
  ua = String(ua || "");

  const ios = /(iphone|ipad|ipod)/i.test(ua);
  const android = /android/i.test(ua);
  const mobile = ios || android || /mobile/i.test(ua);
  const safari =
    /safari/i.test(ua) &&
    !/(crios|fxios|edgios|opios|chrome|chromium)/i.test(ua);

  return { ios, android, mobile, safari };
}

/**
 * Exact compatibility port of V6.3 headerDevice().
 */
export function headerDevice({ ua = "", chMobile = null } = {}) {
  const claim = uaClaim(ua);
  let device = "unknown";

  if (chMobile === "?1" || claim.mobile) {
    device = "mobile";
  } else if (
    chMobile === "?0" ||
    /(windows nt|x11;\s*linux|macintosh)/i.test(ua || "")
  ) {
    device = "desktop";
  }

  return { device, chMobile, claim };
}

export function evaluateV63MobileGate({
  ua = "",
  chMobile = null,
  mobileOnly = true,
} = {}) {
  const detected = headerDevice({ ua, chMobile });

  if (mobileOnly && detected.device === "desktop") {
    return {
      outcome: "block",
      stage: "obvious_desktop",
      reason: "desktop_not_allowed",
      device: detected.device,
      claim: detected.claim,
      chMobile: detected.chMobile,
    };
  }

  return {
    outcome: "continue",
    stage: "post_mobile_gate",
    reason: "mobile_gate_pass",
    device: detected.device,
    claim: detected.claim,
    chMobile: detected.chMobile,
  };
}
