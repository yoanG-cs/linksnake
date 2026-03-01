import { isTrancoSafe } from '../utils/tranco-hash.js';

export function parseURL(url) {
  if (!url) return null;

  try {
    const urlObj = new URL(url);

    if (urlObj.protocol === 'blob:' || urlObj.protocol === 'data:') {
      return {
        full: url,
        domain: urlObj.protocol.replace(':', ''),
        path: urlObj.pathname,
        filename: "generated-file",
        extension: "",
        protocol: urlObj.protocol.replace(':', '')
      };
    }

    const pathParts = urlObj.pathname.split('/');
    let filename = "";
    try {
      filename = decodeURIComponent(pathParts[pathParts.length - 1]);
    } catch {
      filename = pathParts[pathParts.length - 1];
    }

    const extension = filename.includes(".")
      ? filename.substring(filename.lastIndexOf(".")).toLowerCase() : "";

    return {
      full: url,
      domain: urlObj.hostname.toLowerCase(),
      path: urlObj.pathname,
      filename: filename || "unknown",
      extension: extension,
      protocol: urlObj.protocol.replace(':', '')
    };
  } catch (error) {
    console.error("[Parser] Failed to parse URL:", url, error);
    return null;
  }
}

export function checkTLD(lowerDomain, patterns) {
  const profiles = patterns.tlds.tld_risk_profiles;
  if (profiles.critical_risk.some(tld => lowerDomain.endsWith(tld))) return "critical";
  if (profiles.risk.some(tld => lowerDomain.endsWith(tld))) return "risk";
  if (profiles.suspicious.some(tld => lowerDomain.endsWith(tld))) return "suspicious";
  if (profiles.grey_area.some(tld => lowerDomain.endsWith(tld))) return "grey_area";

  return "neutral";
}

export function checkDomain(lowerDomain, patterns, trancoTable) {
  return {
    isTrancoSafe: isTrancoSafe(trancoTable, lowerDomain),
    isShortener: patterns.urlShorteners.url_short.some(s => lowerDomain === s || lowerDomain.endsWith('.' + s)),
    isHighRiskShortener: patterns.urlShorteners.highRisk.some(s => lowerDomain === s || lowerDomain.endsWith('.' + s))
  };
}

export function checkPath(path, patterns) {
  const matches = patterns.pathRules.filter(rule => {
    const regex = new RegExp(rule.pattern, 'i');
    return regex.test(path);
  })

  return {
    matchedRules: matches
  };
}

export function checkHostname(lowerDomain, patterns) {
  const ipv4Pattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

  const isIPv6 = lowerDomain.includes(':') && (
    lowerDomain.includes('[') || /^[0-9a-fA-F:]+$/.test(lowerDomain)
  );

  const isPunycode = lowerDomain.startsWith('xn--');

  return {
    isRawIP: ipv4Pattern.test(lowerDomain) || isIPv6,
    isPunycode: isPunycode,
  };
}

export function checkFilename(filename, patterns) {
  const lowerFile = filename.toLowerCase();
  const parts = lowerFile.split('.');

  const ext = parts.length > 1 ? `.${parts.pop()}` : "";

  const allExecutables = [
    ...patterns.fileExtensions.executable.windows,
    ...patterns.fileExtensions.executable.unix,
    ...patterns.fileExtensions.executable.crossPlatform
  ];

  const hasHiddenExecutable = parts.some(part => allExecutables.includes(`.${part}`));
  const isDouble = hasHiddenExecutable || patterns.fileExtensions.doubleExtensionPatterns.some(p => lowerFile.endsWith(p));

  let type = "unknown";
  const types = patterns.fileExtensions;

  if (allExecutables.includes(ext)) {
    type = "executable";
  } else if (types.macro.includes(ext)) {
    type = "macro";
  } else if (types.archive.includes(ext)) {
    type = "archive";
  } else if (types.script.includes(ext)) {
    type = "script";
  }

  return {
    detectedType: type,
    isDoubleExtension: isDouble,
    extension: ext
  };
}