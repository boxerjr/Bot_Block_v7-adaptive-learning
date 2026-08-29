import test from "node:test";
import assert from "node:assert/strict";
import { browserProbeHtml } from "../src/compat/v63/browser-probe.js";

test("browser probe uses V6.3 canvas-width font detection", () => {
  const html = browserProbeHtml("test-token");

  assert.match(html, /ctx\.measureText\(text\)\.width/);
  assert.match(html, /mmmmmmmmmmlli/);
  assert.match(html, /Segoe UI/);
  assert.match(html, /Calibri/);
  assert.match(html, /Cambria/);
  assert.match(html, /Consolas/);
  assert.doesNotMatch(html, /document\.fonts\.check/);
});
