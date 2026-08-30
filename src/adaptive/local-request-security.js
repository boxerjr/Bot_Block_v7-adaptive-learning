// Local request-target security checks for V7.
//
// Security categories were cross-checked against the public Cloudflare WAF
// rule collection below, then implemented independently for this Worker:
// https://github.com/sefinek/Cloudflare-WAF-Expressions/blob/main/rules/expressions.md
// Inspected expression blob: e102ebcc3d9d0c88fcfef00a5bfc61607b41a5f6
// The upstream project is GPL-3.0. No upstream expression or updater code is
// copied or executed here, and production has no dependency on that project.

export const LOCAL_REQUEST_SECURITY_SOURCE = Object.freeze({
  reference: "sefinek-cloudflare-waf-security-categories",
  referenceBlob: "e102ebcc3d9d0c88fcfef00a5bfc61607b41a5f6",
  implementation: "independent_local",
  runtimeExternalDependency: false,
});

const QUERY_SECRET_MARKERS = Object.freeze([
  ".env",
  "/.env",
  ".env.",
  "appsettings.json",
  "authorized_keys",
  "etc/passwd",
  "etc/shadow",
  "id_dsa",
  "id_ecdsa",
  "id_ed25519",
  "id_rsa",
  "secrets.json",
]);

function boolEnv(value, fallback = true) {
  if (value == null || value === "") return fallback;
  return String(value).trim().toLowerCase() === "true";
}

function decodeRepeated(value, rounds = 2) {
  let current = String(value || "");
  for (let i = 0; i < rounds; i += 1) {
    try {
      const decoded = decodeURIComponent(current);
      if (decoded === current) break;
      current = decoded;
    } catch {
      break;
    }
  }
  return current;
}

function result(path, rule, marker) {
  return {
    matched: true,
    path,
    source: "v7_local_request_security",
    rule,
    matchedPath: marker,
  };
}

function noMatch(path = "/") {
  return {
    matched: false,
    path,
    source: "none",
    rule: null,
    matchedPath: null,
  };
}

export function localRequestSecurityEnabled(env = {}) {
  return boolEnv(env.LOCAL_REQUEST_SECURITY_ENABLED, true);
}

export function classifyLocalRequestThreat(urlValue) {
  const suppliedUrl = String(urlValue || "");
  let url;
  try {
    url = new URL(suppliedUrl);
  } catch {
    return noMatch();
  }

  const path = url.pathname || "/";
  const rawPath = path.toLowerCase();
  const rawQuery = String(url.search || "").slice(1).toLowerCase();
  const rawCombined = `${rawPath}?${rawQuery}`;
  const decodedPath = decodeRepeated(rawPath).toLowerCase();
  const decodedQuery = decodeRepeated(rawQuery.replace(/\+/g, " ")).toLowerCase();
  const decodedCombined = `${decodedPath}?${decodedQuery}`;
  const decodedSuppliedUrl = decodeRepeated(suppliedUrl).toLowerCase();

  if (
    /%(?:00|0a|0d)/i.test(rawCombined) ||
    /[\u0000\r\n]/.test(decodedCombined)
  ) {
    return result(path, "control_character_injection", "null_or_crlf_encoding");
  }

  if (
    decodedPath.includes("../") ||
    decodedPath.includes("..\\") ||
    decodedQuery.includes("../") ||
    decodedQuery.includes("..\\") ||
    decodedSuppliedUrl.includes("../") ||
    decodedSuppliedUrl.includes("..\\")
  ) {
    return result(path, "path_traversal", "parent_directory_sequence");
  }

  if (decodedQuery.includes("php://") || decodedQuery.includes("file://")) {
    return result(path, "dangerous_stream_wrapper", "php_or_file_wrapper");
  }

  if (
    decodedQuery.includes("auto_prepend_file") ||
    decodedQuery.includes("allow_url_include")
  ) {
    return result(path, "php_configuration_injection", "php_runtime_override");
  }

  if (decodedQuery.includes("set-cookie:")) {
    return result(path, "response_splitting_probe", "set_cookie_in_query");
  }

  if (decodedQuery.includes("file_put_contents")) {
    return result(path, "php_code_execution_probe", "file_put_contents");
  }

  if (
    /(?:^|[&=;\s])(?:curl|wget)\s+(?:https?|ftp):\/\//i.test(decodedQuery)
  ) {
    return result(path, "command_download_probe", "curl_or_wget_command");
  }

  const secretMarker = QUERY_SECRET_MARKERS.find((marker) => {
    if (marker === ".env") {
      return /(?:^|[=;&/])\.env(?:$|[.&;/?_-])/.test(decodedQuery);
    }
    return decodedQuery.includes(marker);
  });
  if (secretMarker) {
    return result(path, "secret_file_query_probe", "secret_path_in_query");
  }

  return noMatch(path);
}

export function localRequestSecurityStats() {
  return {
    ruleCategories: 8,
    querySecretMarkers: QUERY_SECRET_MARKERS.length,
    implementation: LOCAL_REQUEST_SECURITY_SOURCE.implementation,
    referenceBlob: LOCAL_REQUEST_SECURITY_SOURCE.referenceBlob,
    runtimeExternalDependency:
      LOCAL_REQUEST_SECURITY_SOURCE.runtimeExternalDependency,
  };
}
