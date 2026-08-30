import { HONEYPOTS } from "../compat/v63/policy.js";

const EXTRA_EXACT = new Map([
  ["/admin", "admin_probe"],
  ["/administrator", "administrator_probe"],
  ["/cpanel", "cpanel_probe"],
  ["/webmail", "webmail_probe"],
  ["/server-status", "apache_server_status"],
  ["/server-info", "apache_server_info"],
  ["/.ds_store", "mac_metadata_probe"],
  ["/composer.json", "composer_manifest_probe"],
  ["/composer.lock", "composer_lock_probe"],
  ["/package.json", "node_manifest_probe"],
  ["/package-lock.json", "node_lock_probe"],
  ["/yarn.lock", "yarn_lock_probe"],
  ["/config.php", "config_php_probe"],
  ["/config.json", "config_json_probe"],
  ["/config.yml", "config_yaml_probe"],
  ["/config.yaml", "config_yaml_probe"],
  ["/settings.py", "django_settings_probe"],
  ["/local.settings.json", "local_settings_probe"],
  ["/web.config", "iis_config_probe"],
  ["/credentials", "credentials_probe"],
  ["/credentials.json", "credentials_probe"],
  ["/secrets", "secrets_probe"],
  ["/secrets.json", "secrets_probe"],
  ["/id_rsa", "ssh_private_key_probe"],
  ["/id_ed25519", "ssh_private_key_probe"],
  ["/authorized_keys", "ssh_keys_probe"],
  ["/id_dsa", "ssh_private_key_probe"],
  ["/id_ecdsa", "ssh_private_key_probe"],
  ["/proc/self/environ", "process_environment_probe"],
  ["/etc/passwd", "passwd_probe"],
  ["/jenkins", "jenkins_probe"],
  ["/grafana", "grafana_probe"],
  ["/prometheus", "prometheus_probe"],
  ["/swagger", "swagger_probe"],
  ["/swagger-ui", "swagger_probe"],
  ["/swagger-ui.html", "swagger_probe"],
  ["/api-docs", "api_docs_probe"],
  ["/v2/api-docs", "api_docs_probe"],
  ["/openapi.json", "openapi_probe"],
  ["/backup", "backup_probe"],
  ["/backups", "backup_probe"],
  ["/site.zip", "archive_probe"],
  ["/www.zip", "archive_probe"],
  ["/public.zip", "archive_probe"],
  ["/source.zip", "archive_probe"],
  ["/src.zip", "archive_probe"],
  ["/backup.rar", "archive_probe"],
  ["/backup.7z", "archive_probe"],
  ["/db.dump", "database_dump_probe"],
  ["/db.gz", "database_dump_probe"],
  ["/dump.gz", "database_dump_probe"],
  ["/sql.sql", "database_dump_probe"],
  ["/phpinfo", "phpinfo_probe"],
  ["/debug", "debug_probe"],
  ["/console", "console_probe"],
  ["/_profiler", "framework_profiler_probe"],
  ["/telescope", "laravel_telescope_probe"],
  ["/boaform/admin/formlogin", "router_admin_probe"],
  ["/hnap1", "router_hnap_probe"],
  ["/appsettings.json", "aspnet_settings_probe"],
  ["/appsettings.production.json", "aspnet_settings_probe"],
  ["/auth.json", "authentication_config_probe"],
  ["/docker-compose.yml", "container_manifest_probe"],
  ["/docker-compose.yaml", "container_manifest_probe"],
  ["/dockerfile", "container_manifest_probe"],
  ["/env.js", "environment_config_probe"],
  ["/key.json", "key_manifest_probe"],
  ["/keys.json", "key_manifest_probe"],
  ["/php.ini", "php_configuration_probe"],
  ["/server.key", "server_private_key_probe"],
  ["/wlwmanifest.xml", "wordpress_manifest_probe"],
  ["/.git-credentials", "git_credentials_probe"],
  ["/.htpasswd", "password_file_probe"],
  ["/.netrc", "network_credentials_probe"],
  ["/.npmrc", "package_registry_credentials_probe"],
  ["/.pypirc", "package_registry_credentials_probe"],
  ["/_all_dbs", "database_inventory_probe"],
  ["/login.action", "java_action_probe"],
  ["/user.action", "java_action_probe"],
]);

const EXTRA_PREFIX = [
  ["/.svn", "svn_metadata_probe"],
  ["/.hg", "mercurial_metadata_probe"],
  ["/.bzr", "bazaar_metadata_probe"],
  ["/.aws", "aws_credentials_probe"],
  ["/.azure", "azure_credentials_probe"],
  ["/.docker", "docker_credentials_probe"],
  ["/.kube", "kubernetes_credentials_probe"],
  ["/.config/gcloud", "gcloud_credentials_probe"],
  ["/wp-admin", "wordpress_admin_probe"],
  ["/phpmyadmin", "phpmyadmin_probe"],
  ["/pma", "phpmyadmin_probe"],
  ["/adminer", "adminer_probe"],
  ["/manager/html", "tomcat_manager_probe"],
  ["/actuator", "spring_actuator_probe"],
  ["/solr/admin", "solr_admin_probe"],
  ["/vendor/phpunit", "phpunit_probe"],
  ["/storage/logs", "application_log_probe"],
  ["/cgi-bin", "cgi_probe"],
  ["/.idea", "ide_metadata_probe"],
  ["/.vscode", "ide_metadata_probe"],
  ["/_debugbar", "framework_debugbar_probe"],
  ["/dbadmin", "database_admin_probe"],
  ["/webdav", "webdav_probe"],
];

const SENSITIVE_ARCHIVE_RE = /(?:^|\/)(?:backup|config|credentials|database|db|dump|secrets|site|source|src|www)(?:[._-][a-z0-9_-]+)?\.(?:7z|bak|bz2|gz|key|log|old|orig|pem|rar|sql|swp|tar|tgz|xz|zip)$/i;

function boolEnv(value, fallback = true) {
  if (value == null || value === "") return fallback;
  return String(value).trim().toLowerCase() === "true";
}

export function honeypotEnforcingEnabled(env = {}) {
  return boolEnv(env.HONEYPOT_ENFORCING, true);
}

export function normalizeHoneypotPath(value = "/") {
  let path = String(value || "/").trim();
  for (let i = 0; i < 2; i += 1) {
    try {
      const decoded = decodeURIComponent(path);
      if (decoded === path) break;
      path = decoded;
    } catch {
      break;
    }
  }

  path = path
    .replace(/\\/g, "/")
    .replace(/\/{2,}/g, "/")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .toLowerCase();

  if (!path.startsWith("/")) path = `/${path}`;
  if (path.length > 1 && path.endsWith("/")) path = path.slice(0, -1);
  return path || "/";
}

function prefixMatch(path, prefix) {
  return path === prefix || path.startsWith(`${prefix}/`);
}

export function classifyHoneypotPath(pathValue = "/") {
  const path = normalizeHoneypotPath(pathValue);

  // Catch .env variants including encoded/case-obfuscated forms such as
  // /.ENV.production, /.env.bak and /%2eenv.local.
  if (
    path === "/.env" ||
    path.startsWith("/.env.") ||
    path.startsWith("/.env-") ||
    path.startsWith("/.env_")
  ) {
    return {
      matched: true,
      path,
      source: "v7_extended",
      rule: "environment_secret_probe",
      matchedPath: "/.env*",
    };
  }

  if (SENSITIVE_ARCHIVE_RE.test(path)) {
    return {
      matched: true,
      path,
      source: "v7_extended",
      rule: "sensitive_archive_probe",
      matchedPath: "sensitive_name_plus_archive_extension",
    };
  }

  for (const baseline of HONEYPOTS) {
    const normalized = normalizeHoneypotPath(baseline);
    if (prefixMatch(path, normalized)) {
      return {
        matched: true,
        path,
        source: "v63_baseline",
        rule: "baseline_honeypot",
        matchedPath: normalized,
      };
    }
  }

  const exactRule = EXTRA_EXACT.get(path);
  if (exactRule) {
    return {
      matched: true,
      path,
      source: "v7_extended",
      rule: exactRule,
      matchedPath: path,
    };
  }

  for (const [prefix, rule] of EXTRA_PREFIX) {
    if (prefixMatch(path, prefix)) {
      return {
        matched: true,
        path,
        source: "v7_extended",
        rule,
        matchedPath: prefix,
      };
    }
  }

  return {
    matched: false,
    path,
    source: "none",
    rule: null,
    matchedPath: null,
  };
}

export function honeypotRuleStats() {
  return {
    baseline: HONEYPOTS.length,
    extendedExact: EXTRA_EXACT.size,
    extendedPrefix: EXTRA_PREFIX.length,
    envVariantRule: 1,
    sensitiveArchiveRule: 1,
    totalRuleEntries:
      HONEYPOTS.length + EXTRA_EXACT.size + EXTRA_PREFIX.length + 2,
  };
}
