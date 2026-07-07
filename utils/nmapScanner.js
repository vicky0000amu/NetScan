const { execFile } = require("child_process");
const xml2js = require("xml2js");

// ----------------------------------------------------------------------
// Allowed scan "profiles". We deliberately do NOT let the user pass raw
// nmap flags. Instead they pick from a fixed menu, and we map that menu
// choice to a hardcoded argument array. This is the single most important
// security decision in this whole project: it makes command injection
// impossible because user input is NEVER concatenated into a shell string.
// ----------------------------------------------------------------------
const SCAN_PROFILES = {
  ping: {
    label: "Host Discovery (ping only, no ports)",
    args: ["-sn"],
  },
  quick: {
    label: "Quick Scan (top 100 ports)",
    args: ["-T4", "-F"],
  },
  standard: {
    label: "Standard Scan (top 1000 ports + service versions)",
    args: ["-T4", "-sV"],
  },
  full: {
    label: "Full Scan (all 65535 ports, slower)",
    args: ["-T4", "-p-"],
  },
};

// Basic allowlist regex for a target: IPv4, IPv6-ish, or hostname characters only.
// This blocks shell metacharacters (; | & $ ` > < ( ) etc.) even though we
// already avoid the shell entirely by using execFile with an argument array.
// Defense in depth: validate AND avoid the shell.
const TARGET_REGEX = /^[a-zA-Z0-9.\-:]{1,255}$/;

function isValidTarget(target) {
  return typeof target === "string" && TARGET_REGEX.test(target.trim());
}

function getProfile(profileKey) {
  return SCAN_PROFILES[profileKey] || null;
}

function listProfiles() {
  return Object.entries(SCAN_PROFILES).map(([key, val]) => ({
    key,
    label: val.label,
  }));
}

/**
 * Runs nmap against a single target using a fixed profile.
 * Returns a parsed, easy-to-render JS object.
 */
function runScan(target, profileKey) {
  return new Promise((resolve, reject) => {
    if (!isValidTarget(target)) {
      return reject(new Error("Invalid target. Use a plain hostname or IP address."));
    }

    const profile = getProfile(profileKey);
    if (!profile) {
      return reject(new Error("Invalid scan profile selected."));
    }

    // -oX - => write XML results to stdout so we can parse them.
    const args = [...profile.args, "-oX", "-", target.trim()];

    // execFile does NOT spawn a shell, so shell metacharacters in `target`
    // are treated as literal text, not commands - even if they slipped
    // past the regex above.
    execFile(
      "nmap",
      args,
      { timeout: 120000, maxBuffer: 1024 * 1024 * 10 }, // 2 min timeout, 10MB buffer
      (error, stdout, stderr) => {
        if (error && !stdout) {
          return reject(new Error(stderr || error.message));
        }

        xml2js.parseString(stdout, (parseErr, result) => {
          if (parseErr) {
            return reject(new Error("Failed to parse nmap output."));
          }
          resolve(formatResult(result));
        });
      }
    );
  });
}

/**
 * Converts nmap's verbose XML->JSON structure into something simple
 * an EJS template (or frontend JS) can loop over without pain.
 */
function formatResult(raw) {
  const nmaprun = raw.nmaprun;
  const hosts = [];

  if (!nmaprun || !nmaprun.host) {
    return { hosts: [], scanInfo: null };
  }

  const hostList = Array.isArray(nmaprun.host) ? nmaprun.host : [nmaprun.host];

  for (const host of hostList) {
    const address = host.address ? host.address[0].$.addr : "unknown";
    const status = host.status ? host.status[0].$.state : "unknown";

    let hostname = null;
    if (host.hostnames && host.hostnames[0].hostname) {
      hostname = host.hostnames[0].hostname[0].$.name;
    }

    const ports = [];
    if (host.ports && host.ports[0].port) {
      for (const p of host.ports[0].port) {
        ports.push({
          port: p.$.portid,
          protocol: p.$.protocol,
          state: p.state ? p.state[0].$.state : "unknown",
          service: p.service ? p.service[0].$.name : "unknown",
          product: p.service && p.service[0].$.product ? p.service[0].$.product : "",
          version: p.service && p.service[0].$.version ? p.service[0].$.version : "",
        });
      }
    }

    hosts.push({ address, hostname, status, ports });
  }

  const scanInfo = {
    args: nmaprun.$.args || "",
    startStr: nmaprun.$.startstr || "",
    version: nmaprun.$.version || "",
  };

  return { hosts, scanInfo };
}

module.exports = {
  runScan,
  isValidTarget,
  listProfiles,
};
