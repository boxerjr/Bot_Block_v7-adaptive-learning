function normalizeOrganization(value) {
  return String(value || "")
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/&/g, " and ")
    .replace(/[^a-z0-9]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function result(classification, confidence, riskDelta, matchedRule, reason) {
  return {
    class: classification,
    confidence,
    riskDelta,
    matchedRule,
    reason,
    source: "cloudflare_asOrganization",
    hardBlock: false,
  };
}

const VPN_PROXY_RULES = [
  [/(^| )consumer vpn( |$)/, "consumer_vpn"],
  [/(^| )vpn( |$)/, "vpn_keyword"],
  [/(^| )proxy( |$)/, "proxy_keyword"],
  [/(^| )residential proxy( |$)/, "residential_proxy"],
  [/(^| )anonym(izer|ization|ous)?( |$)/, "anonymizer_keyword"],
  [/(^| )tor exit( |$)/, "tor_exit"],
  [/(^| )privacy network( |$)/, "privacy_network"],
];

const HOSTING_CLOUD_RULES = [
  [/(^| )digitalocean( |$)/, "digitalocean"],
  [/(^| )ionos( |$)/, "ionos"],
  [/(^| )ovh( |$)/, "ovh"],
  [/(^| )hetzner( |$)/, "hetzner"],
  [/(^| )vultr( |$)/, "vultr"],
  [/(^| )linode( |$)/, "linode"],
  [/(^| )leaseweb( |$)/, "leaseweb"],
  [/(^| )contabo( |$)/, "contabo"],
  [/(^| )scaleway( |$)/, "scaleway"],
  [/(^| )hostinger( |$)/, "hostinger"],
  [/(^| )choopa( |$)/, "choopa"],
  [/(^| )datacamp( |$)/, "datacamp"],
  [/(^| )amazon web services( |$)/, "amazon_web_services"],
  [/(^| )amazon aws( |$)/, "amazon_aws"],
  [/(^| )google cloud( |$)/, "google_cloud"],
  [/(^| )oracle cloud( |$)/, "oracle_cloud"],
  [/(^| )microsoft azure( |$)/, "microsoft_azure"],
  [/(^| )akamai connected cloud( |$)/, "akamai_connected_cloud"],
  [/(^| )equinix metal( |$)/, "equinix_metal"],
];

const SPAIN_CONSUMER_ISP_RULES = [
  [/(^| )telefonica de espana( |$)/, "telefonica_spain"],
  [/(^| )telefonica moviles espana( |$)/, "telefonica_mobile_spain"],
  [/(^| )movistar( |$)/, "movistar"],
  [/(^| )digi spain telecom( |$)/, "digi_spain"],
  [/(^| )digi mobil( |$)/, "digi_mobile"],
  [/(^| )orange spain( |$)/, "orange_spain"],
  [/(^| )orange espagne( |$)/, "orange_spain_fr"],
  [/(^| )vodafone espana( |$)/, "vodafone_spain"],
  [/(^| )vodafone spain( |$)/, "vodafone_spain_en"],
  [/(^| )jazztel( |$)/, "jazztel"],
  [/(^| )masmovil( |$)/, "masmovil"],
  [/(^| )xfera( |$)/, "xfera"],
  [/(^| )yoigo( |$)/, "yoigo"],
  [/(^| )euskaltel( |$)/, "euskaltel"],
  [/(^| )telecable( |$)/, "telecable"],
  [/(^| )avatel( |$)/, "avatel"],
  [/(^| )adamo telecom( |$)/, "adamo"],
  [/(^| )finetwork( |$)/, "finetwork"],
];

const GENERIC_ACCESS_RULES = [
  [/(^| )(mobile|movil|cellular) (telecom|communications|network)( |$)/, "mobile_carrier_generic", "mobile_carrier"],
  [/(^| )(broadband|fiber|fibre|cable) (network|telecom|internet)( |$)/, "consumer_access_generic", "consumer_isp"],
  [/(^| )internet service provider( |$)/, "isp_generic", "consumer_isp"],
];

function matchRules(normalized, rules) {
  for (const [pattern, name, classification] of rules) {
    if (pattern.test(normalized)) return { name, classification };
  }
  return null;
}

export function classifyOrganization(value) {
  const normalized = normalizeOrganization(value);
  if (!normalized) {
    return result("unknown", 0, 0, "none", "organization_unavailable");
  }

  const vpn = matchRules(normalized, VPN_PROXY_RULES);
  if (vpn) {
    return result(
      "vpn_proxy",
      99,
      22,
      vpn.name,
      "organization_matches_vpn_or_proxy_infrastructure"
    );
  }

  const hosting = matchRules(normalized, HOSTING_CLOUD_RULES);
  if (hosting) {
    return result(
      "hosting_cloud",
      99,
      14,
      hosting.name,
      "organization_matches_hosting_or_cloud_infrastructure"
    );
  }

  const consumer = matchRules(normalized, SPAIN_CONSUMER_ISP_RULES);
  if (consumer) {
    return result(
      "consumer_isp",
      99,
      0,
      consumer.name,
      "organization_matches_known_consumer_access_provider"
    );
  }

  const generic = matchRules(normalized, GENERIC_ACCESS_RULES);
  if (generic) {
    return result(
      generic.classification || "consumer_isp",
      72,
      0,
      generic.name,
      "organization_looks_like_access_network"
    );
  }

  return result("unknown", 30, 0, "none", "organization_not_classified");
}

export function organizationRiskDelta(value) {
  return classifyOrganization(value).riskDelta;
}
