// The scan itself — secrets and dependencies, entirely in the browser.
//
// Nothing here sends the repository anywhere. File contents are fetched from
// GitHub, scanned in this worker, and discarded; the only outbound request the
// scan makes is to OSV, and it carries package names and versions, never code.
// That is the whole reason this runs client-side: a security tool that uploads
// your source to a server to look for secrets in it is a hard thing to defend.
//
// The third detector — bandit and eslint-plugin-security — cannot run here.
// They are subprocesses over a directory tree. The UI says so rather than
// quietly reporting a two-thirds scan as a clean bill of health.

import { SECRET_RULES } from "./rules.generated.js";

// ---------------------------------------------------------------------------
// Shared helpers, mirroring reposec/detectors/common.py
// ---------------------------------------------------------------------------
const VENDOR_DIRS = new Set([
  "node_modules", "vendor", "third_party", "bower_components", ".venv", "venv",
  "env", "site-packages", "dist", "build", "target", "out", "__pycache__",
  ".mypy_cache", ".pytest_cache", ".tox", "coverage", ".next", ".nuxt", ".git",
]);

const SKIP_SUFFIXES = [
  ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg", ".pdf",
  ".zip", ".gz", ".tar", ".bz2", ".xz", ".7z", ".rar", ".woff", ".woff2",
  ".ttf", ".eot", ".otf", ".mp3", ".mp4", ".avi", ".mov", ".wav", ".so",
  ".dll", ".dylib", ".exe", ".bin", ".class", ".jar", ".pyc", ".map",
  ".min.js", ".min.css", ".snap",
];

export function isVendored(path) {
  return path.split("/").some((part) => VENDOR_DIRS.has(part));
}

export function isScannable(path) {
  const lower = path.toLowerCase();
  if (isVendored(lower)) return false;
  return !SKIP_SUFFIXES.some((s) => lower.endsWith(s));
}

// Shannon entropy in bits per character. Random base64 sits near 5.5-6.0;
// prose and identifiers sit near 3.0-4.0.
export function shannonEntropy(value) {
  if (!value) return 0;
  const counts = new Map();
  for (const ch of value) counts.set(ch, (counts.get(ch) || 0) + 1);
  let total = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    total -= p * Math.log2(p);
  }
  return total;
}

// Show enough to locate the secret, never enough to use it.
export function redact(secret) {
  const s = secret.trim();
  if (s.length <= 8) return "*".repeat(s.length);
  return `${s.slice(0, 3)}${"*".repeat(8)}${s.slice(-3)} (${s.length} chars)`;
}

// ---------------------------------------------------------------------------
// Placeholder suppression — the single biggest source of false positives
// ---------------------------------------------------------------------------
const EXAMPLE_FILE_RE =
  /(^|\/)(\.env\.(example|sample|template|dist)|.*\.example($|\.)|.*\.sample($|\.)|.*\.template($|\.))/i;

const PLACEHOLDER_TOKENS = [
  "example", "sample", "placeholder", "changeme", "change_me", "yourkey",
  "your_key", "your-key", "yoursecret", "your_secret", "dummy", "notreal",
  "fake", "insert", "redacted", "xxxxxx", "aaaaaa", "000000", "123456",
  "abcdef", "test-key", "testkey", "mykey", "foobar", "lorem",
];

const PLACEHOLDER_SHAPE_RE = /(\$\{[^}]*\}|\{\{[^}]*\}\}|<[^>]{2,}>|%\([a-z_]+\)s|\$[A-Z_]{3,})/;
const ANNOTATION_RE = /\b(e\.g\.|for example|replace with|see docs)\b/i;

export function isPlaceholder(secret, line) {
  const low = secret.toLowerCase();
  if (PLACEHOLDER_TOKENS.some((t) => low.includes(t))) return true;
  if (PLACEHOLDER_SHAPE_RE.test(secret) || PLACEHOLDER_SHAPE_RE.test(line)) return true;
  if (ANNOTATION_RE.test(line)) return true;
  // A single repeated character is never a secret.
  const stripped = secret.replace(/[^A-Za-z0-9]/g, "");
  return new Set(stripped).size <= 2 && stripped.length >= 6;
}

// ---------------------------------------------------------------------------
// Detector 1 — secrets
// ---------------------------------------------------------------------------
export function scanFileForSecrets(path, content) {
  if (!isScannable(path) || !content.trim() || content.includes("\0")) return [];

  const isExample = EXAMPLE_FILE_RE.test(path);
  const lines = content.split("\n");
  const findings = [];
  const seen = new Set();

  for (const rule of SECRET_RULES) {
    const re = new RegExp(rule.pattern, rule.flags);
    let match;
    while ((match = re.exec(content)) !== null) {
      // A zero-length match would loop forever.
      if (match[0] === "") { re.lastIndex += 1; continue; }

      const lineNo = content.slice(0, match.index).split("\n").length;
      const key = `${rule.id}:${lineNo}`;
      if (seen.has(key)) continue;

      const line = lines[lineNo - 1] || "";
      const secret = rule.group ? (match[1] ?? match[0]) : match[0];

      if (isExample || isPlaceholder(secret, line)) continue;
      if (rule.minEntropy && shannonEntropy(secret) < rule.minEntropy) continue;

      seen.add(key);
      findings.push({
        id: `${rule.id}:${path}:${lineNo}`,
        category: "secret",
        detector: rule.minEntropy ? "regex+entropy" : "gitleaks-regex",
        rule_id: rule.id,
        title: rule.title,
        file: path,
        line_start: lineNo,
        severity: rule.severity,
        evidence: redact(secret),
        explanation: rule.explanation,
        suggested_fix: rule.remediation,
        references: rule.references,
      });
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Detector 2 — dependencies, via OSV
// ---------------------------------------------------------------------------
const EXACT_NPM = /^\d+\.\d+\.\d+$/;
// Extras (`requests[socks]==2.31.0`) are stripped with a separate pass rather
// than matched inline. Inlining them needs `(?:\[[^\]]*\])?` — a quantifier
// inside an optional group — which backtracks badly on a crafted line, and a
// requirements.txt from an arbitrary repository is exactly the attacker-
// controlled input that reaches here. eslint-plugin-security caught this in the
// original expression, running under this scanner.
const EXTRAS = /\[[^\]]*\]/;
const REQ_LINE = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([A-Za-z0-9][\w.!+-]*)/;
const REQ_UNPINNED = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*[<>~!^]/;

export function parseManifests(files) {
  const packages = [];
  const unpinned = [];
  const haveNpmLock = files.some(
    (f) => /(^|\/)(package-lock\.json|yarn\.lock)$/.test(f.path) && !isVendored(f.path)
  );

  for (const { path, content } of files) {
    if (isVendored(path)) continue;
    const name = path.split("/").pop();

    if (/(^|\/)(requirements[\w.-]*\.txt|constraints[\w.-]*\.txt)$/.test(path)) {
      for (const raw of content.split("\n")) {
        const line = raw.split("#")[0].trim().replace(EXTRAS, "");
        if (!line || line.startsWith("-")) continue;
        const m = REQ_LINE.exec(line);
        if (m) packages.push({ name: m[1].toLowerCase(), version: m[2], ecosystem: "PyPI", manifest: path });
        else {
          const u = REQ_UNPINNED.exec(line);
          if (u) unpinned.push(u[1]);
        }
      }
    } else if (name === "package-lock.json") {
      try {
        const data = JSON.parse(content);
        for (const [key, spec] of Object.entries(data.packages || {})) {
          if (!key.includes("node_modules/")) continue;
          const pkg = key.split("node_modules/").pop();
          if (pkg && spec?.version) {
            packages.push({ name: pkg, version: spec.version, ecosystem: "npm", manifest: path });
          }
        }
        // lockfileVersion 1 keeps a nested tree instead.
        const walk = (node) => {
          for (const [pkg, spec] of Object.entries(node.dependencies || {})) {
            if (spec?.version) {
              packages.push({ name: pkg, version: spec.version, ecosystem: "npm", manifest: path });
            }
            if (spec && typeof spec === "object") walk(spec);
          }
        };
        if (!Object.keys(data.packages || {}).length) walk(data);
      } catch { /* a malformed lockfile is not worth failing the scan over */ }
    } else if (name === "package.json" && !haveNpmLock) {
      try {
        const data = JSON.parse(content);
        for (const section of ["dependencies", "devDependencies", "optionalDependencies"]) {
          for (const [pkg, spec] of Object.entries(data[section] || {})) {
            // A range: only the lockfile knows what actually got installed, and
            // checking the wrong version is worse than checking nothing.
            if (typeof spec === "string" && EXACT_NPM.test(spec.trim())) {
              packages.push({ name: pkg, version: spec.trim(), ecosystem: "npm", manifest: path });
            } else unpinned.push(pkg);
          }
        }
      } catch { /* ignore */ }
    }
  }

  // Deduplicate: the same package at the same version in two manifests is one
  // dependency to check.
  const seen = new Map();
  for (const p of packages) seen.set(`${p.ecosystem}:${p.name}:${p.version}`, p);
  return { packages: [...seen.values()], unpinned: [...new Set(unpinned)] };
}

const SEVERITY_WORDS = {
  CRITICAL: "high", HIGH: "high", MODERATE: "medium", MEDIUM: "medium", LOW: "low",
};

function severityOf(vuln) {
  const explicit = vuln.database_specific?.severity;
  if (explicit && SEVERITY_WORDS[explicit.toUpperCase()]) {
    return SEVERITY_WORDS[explicit.toUpperCase()];
  }
  // No severity data (common for PySec records): stay visible without claiming
  // a criticality the data does not support.
  return "medium";
}

function fixedVersionFor(vuln, pkg) {
  const candidates = [];
  for (const affected of vuln.affected || []) {
    if ((affected.package?.name || "").toLowerCase() !== pkg.name.toLowerCase()) continue;
    for (const range of affected.ranges || []) {
      for (const event of range.events || []) {
        if (event.fixed) candidates.push(event.fixed);
      }
    }
  }
  const key = (v) => v.split(/[.\-+]/).map((p) => (/^\d+$/.test(p) ? p.padStart(8, "0") : p)).join(".");
  const ahead = candidates.filter((c) => key(c) > key(pkg.version)).sort();
  return ahead[0] || null;
}

export async function scanDependencies(files, { fetchImpl = fetch } = {}) {
  const { packages, unpinned } = parseManifests(files);
  const degraded = [];

  if (!packages.length) {
    degraded.push(
      unpinned.length
        ? `dependency: no pinned versions found (${unpinned.slice(0, 5).join(", ")}…). Commit a lockfile so versions can be checked.`
        : "dependency: no supported manifest files found"
    );
    return { findings: [], degraded };
  }

  let results;
  try {
    const resp = await fetchImpl("https://api.osv.dev/v1/querybatch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        queries: packages.map((p) => ({
          version: p.version,
          package: { name: p.name, ecosystem: p.ecosystem },
        })),
      }),
    });
    if (!resp.ok) throw new Error(`OSV returned ${resp.status}`);
    results = (await resp.json()).results || [];
  } catch (e) {
    // An unreachable database must never read as "no vulnerabilities".
    degraded.push(`dependency: OSV unreachable (${e.message}) — versions not checked`);
    return { findings: [], degraded };
  }

  const ids = new Map();
  results.forEach((entry, i) => {
    for (const v of entry?.vulns || []) if (v.id) ids.set(v.id, packages[i]);
  });

  const findings = [];
  // OSV has no batch detail endpoint, so this is one request per vulnerability.
  const details = await Promise.all(
    [...ids.keys()].slice(0, 150).map(async (id) => {
      try {
        const r = await fetchImpl(`https://api.osv.dev/v1/vulns/${id}`);
        return r.ok ? await r.json() : null;
      } catch { return null; }
    })
  );

  for (const vuln of details) {
    if (!vuln) continue;
    const pkg = ids.get(vuln.id);
    if (!pkg) continue;
    const cve = (vuln.aliases || []).find((a) => a.startsWith("CVE-")) || vuln.id;
    const fixed = fixedVersionFor(vuln, pkg);
    findings.push({
      id: `${cve}:${pkg.name}:${pkg.version}`,
      category: "dependency",
      detector: "osv",
      rule_id: cve,
      title: `${pkg.name} ${pkg.version} — ${cve}`,
      file: pkg.manifest,
      line_start: 0,
      severity: severityOf(vuln),
      evidence: `${pkg.ecosystem}:${pkg.name}@${pkg.version}`,
      explanation: `${pkg.name} ${pkg.version} is affected by ${cve}: ${vuln.summary || (vuln.details || "").split("\n")[0] || "No description published."}`,
      suggested_fix: fixed
        ? `Upgrade ${pkg.name} from ${pkg.version} to ${fixed} or later in ${pkg.manifest}.`
        : `No fixed version is published for ${pkg.name} ${pkg.version}. Check the advisory for a workaround.`,
      references: [`https://osv.dev/vulnerability/${vuln.id}`],
    });
  }

  if (unpinned.length) {
    degraded.push(
      `dependency: ${unpinned.length} unpinned requirement(s) skipped (${unpinned.slice(0, 5).join(", ")}…) — commit a lockfile to include them`
    );
  }
  return { findings, degraded };
}

// ---------------------------------------------------------------------------
// Suppression (.secscanignore), mirroring reposec/detectors/suppress.py
// ---------------------------------------------------------------------------
export function parseSuppressions(text) {
  const rules = [];
  for (const raw of text.split("\n")) {
    const line = raw.split("#")[0].trim();
    if (!line) continue;
    const idx = line.indexOf(":");
    const pathGlob = (idx === -1 ? line : line.slice(0, idx)).trim();
    const ruleId = (idx === -1 ? "" : line.slice(idx + 1)).trim();
    if (!pathGlob && !ruleId) continue;
    rules.push({ pathGlob, ruleId });
  }
  return rules;
}

function globMatches(glob, path) {
  const clean = (s) => s.replace(/\\/g, "/").replace(/^\.\//, "");
  path = clean(path);
  glob = clean(glob);
  const prefix = glob.replace(/\/$/, "").replace(/\/\*\*$/, "");
  if (prefix && path.startsWith(prefix + "/")) return true;
  const re = new RegExp(
    "^" + glob.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$"
  );
  return re.test(path);
}

export function applySuppressions(findings, rules) {
  if (!rules.length) return { kept: findings, suppressed: 0 };
  const kept = findings.filter(
    (f) =>
      !rules.some(
        (r) =>
          (!r.ruleId || r.ruleId === f.rule_id) &&
          (!r.pathGlob || globMatches(r.pathGlob, f.file))
      )
  );
  return { kept, suppressed: findings.length - kept.length };
}

// ---------------------------------------------------------------------------
// Assembling a report
// ---------------------------------------------------------------------------
const SEVERITY_ORDER = { high: 0, medium: 1, low: 2 };

export function aggregate(findings, { scannedFiles, skippedFiles, suppressed, degraded }) {
  // Same rule as the CLI: one problem found twice is one finding.
  const groups = new Map();
  for (const f of findings) {
    const key =
      f.category === "dependency"
        ? `${f.category}|${f.rule_id}|${f.evidence}`
        : `${f.category}|${f.file}|${f.line_start}`;
    const existing = groups.get(key);
    if (!existing || SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[existing.severity]) {
      groups.set(key, f);
    }
  }
  const unique = [...groups.values()].sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      a.file.localeCompare(b.file) ||
      a.line_start - b.line_start
  );

  const counts = { high: 0, medium: 0, low: 0 };
  const byCategory = { secret: 0, dependency: 0, code: 0 };
  for (const f of unique) {
    counts[f.severity] += 1;
    byCategory[f.category] += 1;
  }

  const parts = [];
  if (byCategory.secret) parts.push(`${byCategory.secret} exposed secret${byCategory.secret === 1 ? "" : "s"}`);
  if (byCategory.dependency) parts.push(`${byCategory.dependency} vulnerable ${byCategory.dependency === 1 ? "dependency" : "dependencies"}`);

  return {
    summary: unique.length
      ? `${unique.length} finding${unique.length === 1 ? "" : "s"} (${counts.high} high, ${counts.medium} medium, ${counts.low} low): ${parts.join(", ")}.`
      : "No secrets or vulnerable dependencies found.",
    findings: unique,
    counts_by_severity: counts,
    counts_by_category: byCategory,
    scanned_files: scannedFiles,
    skipped_files: skippedFiles,
    suppressed,
    degraded,
  };
}
