function jsString(value) {
  return JSON.stringify(String(value));
}

export function browserProbeHtml(token) {
  const TOKEN = jsString(token);

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>V7 M1 Browser Probe</title>
<style>
body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:24px;line-height:1.45}
main{max-width:820px;margin:auto}
pre{white-space:pre-wrap;word-break:break-word;background:#111;color:#eee;padding:16px;border-radius:10px}
</style>
</head>
<body>
<main>
<h1>V7 M1 Browser Probe</h1>
<p id="state">Collecting real browser telemetry in shadow mode…</p>
<pre id="output">Please wait.</pre>
</main>
<script>
(() => {
  "use strict";
  const TOKEN = ${TOKEN};
  const started = performance.now();
  const passive = { total:0, trusted:0, pointer:0, mouse:0, touch:0, key:0 };

  for (const type of ["pointermove","pointerdown","mousemove","mousedown","touchstart","keydown"]) {
    addEventListener(type, event => {
      passive.total++;
      if (event.isTrusted) passive.trusted++;
      if (type.startsWith("pointer")) passive.pointer++;
      else if (type.startsWith("mouse")) passive.mouse++;
      else if (type.startsWith("touch")) passive.touch++;
      else if (type.startsWith("key")) passive.key++;
    }, { passive:true });
  }

  function mq(query) {
    try { return matchMedia(query).matches; } catch { return null; }
  }

  function webglInfo() {
    try {
      const canvas = document.createElement("canvas");
      const gl = canvas.getContext("webgl2") || canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
      if (!gl) return {};
      const ext = gl.getExtension("WEBGL_debug_renderer_info");
      return {
        vendor: ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR),
        renderer: ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER)
      };
    } catch { return {}; }
  }

  async function webgpuInfo() {
    try {
      if (!navigator.gpu) return {};
      const adapter = await navigator.gpu.requestAdapter();
      if (!adapter) return {};
      let info = adapter.info || null;
      if (!info && typeof adapter.requestAdapterInfo === "function") info = await adapter.requestAdapterInfo();
      return {
        vendor: info?.vendor || null,
        architecture: info?.architecture || null,
        description: info?.description || null,
        device: info?.device || null
      };
    } catch { return {}; }
  }

  async function uaDataInfo() {
    try {
      const data = navigator.userAgentData;
      if (!data) return { present:false };
      const result = {
        present:true,
        mobile: typeof data.mobile === "boolean" ? data.mobile : null,
        platform: data.platform || null,
        brands: Array.isArray(data.brands) ? data.brands.slice(0,8) : []
      };
      if (typeof data.getHighEntropyValues === "function") {
        const high = await data.getHighEntropyValues([
          "architecture","bitness","model","platformVersion","uaFullVersion","fullVersionList"
        ]);
        result.architecture = high.architecture || null;
        result.bitness = high.bitness || null;
        result.model = high.model || null;
        result.platformVersion = high.platformVersion || null;
        result.uaFullVersion = high.uaFullVersion || null;
      }
      return result;
    } catch { return { present:!!navigator.userAgentData }; }
  }

  // Exact V6.3 canvas-width font detection. Do not replace with
  // document.fonts.check(): Safari font fallback can produce false positives.
  function fontSignals() {
    try {
      const text = "mmmmmmmmmmlli";
      const canvas = document.createElement("canvas");
      const ctx = canvas.getContext("2d");
      if (!ctx) return [];

      const bases = ["monospace", "sans-serif", "serif"];
      const wanted = ["Segoe UI", "Calibri", "Cambria", "Consolas", "Arial", "Helvetica Neue"];
      const baseline = {};

      for (const base of bases) {
        ctx.font = "72px " + base;
        baseline[base] = ctx.measureText(text).width;
      }

      const result = [];
      for (const font of wanted) {
        let present = false;
        for (const base of bases) {
          ctx.font = '72px "' + font + '",' + base;
          if (Math.abs(ctx.measureText(text).width - baseline[base]) > 0.01) {
            present = true;
            break;
          }
        }
        if (present) result.push(font);
      }

      return result;
    } catch { return []; }
  }

  function automationSignals() {
    try {
      const html = document.documentElement;
      const keys = Object.keys(window);
      return {
        selenium: !!window._selenium || !!window.__selenium_unwrapped || !!window.__webdriver_evaluate,
        phantom: !!window.callPhantom || !!window._phantom,
        nightmare: !!window.__nightmare,
        webdriverAttr: !!html?.getAttribute("webdriver"),
        cdc: keys.some(key => /^cdc_[a-zA-Z0-9]+_/.test(key))
      };
    } catch {
      return {};
    }
  }

  async function collect() {
    const gpu = await webgpuInfo();
    const uaData = await uaDataInfo();
    return {
      navigator: {
        userAgent: navigator.userAgent || "",
        platform: navigator.platform || "",
        vendor: navigator.vendor || "",
        productSub: navigator.productSub || "",
        language: navigator.language || "",
        languages: Array.isArray(navigator.languages) ? navigator.languages.slice(0,12) : [],
        webdriver: navigator.webdriver === true,
        maxTouchPoints: Number(navigator.maxTouchPoints || 0),
        hardwareConcurrency: Number(navigator.hardwareConcurrency || 0),
        deviceMemory: Number(navigator.deviceMemory || 0),
        pluginsLength: Number(navigator.plugins?.length || 0),
        mimeTypesLength: Number(navigator.mimeTypes?.length || 0)
      },
      uaData,
      window: { chromePresent: !!window.chrome },
      media: {
        pointerFine: mq("(pointer:fine)"),
        pointerCoarse: mq("(pointer:coarse)"),
        anyHoverHover: mq("(any-hover:hover)")
      },
      webgl: webglInfo(),
      webgpu: gpu,
      fonts: fontSignals(),
      automation: automationSignals(),
      capabilities: {
        serial: !!navigator.serial,
        usb: !!navigator.usb,
        hid: !!navigator.hid,
        bluetooth: !!navigator.bluetooth,
        getScreenDetails: typeof window.getScreenDetails === "function",
        fileSystemAccess: typeof window.showOpenFilePicker === "function" || typeof window.showSaveFilePicker === "function"
      },
      performance: { memoryPresent: !!performance.memory },
      screen: {
        width: Number(screen.width || 0),
        height: Number(screen.height || 0),
        availWidth: Number(screen.availWidth || 0),
        availHeight: Number(screen.availHeight || 0),
        colorDepth: Number(screen.colorDepth || 0),
        pixelRatio: Number(devicePixelRatio || 1)
      },
      timezone: {
        name: (() => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || null; } catch { return null; } })(),
        offset: new Date().getTimezoneOffset()
      },
      interaction: {
        total: passive.total,
        trusted: passive.trusted,
        trustedRatio: passive.total ? Number((passive.trusted / passive.total).toFixed(3)) : 1,
        pointer: passive.pointer,
        mouse: passive.mouse,
        touch: passive.touch,
        key: passive.key
      },
      elapsed: Number((performance.now() - started).toFixed(2))
    };
  }

  (async () => {
    try {
      await new Promise(resolve => setTimeout(resolve, 450));
      const telemetry = await collect();
      const response = await fetch("/_shadow/browser-probe-submit", {
        method: "POST",
        credentials: "same-origin",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token:TOKEN, telemetry })
      });
      const data = await response.json();
      document.getElementById("state").textContent = response.ok
        ? "Probe complete. This remains shadow-only and is excluded from training."
        : "Probe failed.";
      document.getElementById("output").textContent = JSON.stringify(data, null, 2);
    } catch (error) {
      document.getElementById("state").textContent = "Probe failed.";
      document.getElementById("output").textContent = String(error?.message || error);
    }
  })();
})();
</script>
</body>
</html>`;
}
