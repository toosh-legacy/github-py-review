// Parity: the browser scanner must agree with the Python one.
//
// Two implementations of a secret rule set will drift, and a drifted scanner
// misses things exactly where nobody is looking. So this runs the JS detector
// over the same labelled benchmark fixture the Python detector scores against,
// and asserts the same planted findings and the same silence on the decoys.
//
//     node --test tests/js/
//
// Run from the repo root.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

import {
  aggregate,
  applySuppressions,
  isPlaceholder,
  isScannable,
  parseManifests,
  parseSuppressions,
  redact,
  scanFileForSecrets,
  shannonEntropy,
} from "../../src/apps/extension/scanner.js";

const BENCH = "src/evaluation/security_benchmark";

// The corpus is stored base64-encoded rather than as files on disk: it is a
// repository full of deliberately-planted credentials, which every scanner in
// the world flags — including GitHub's push protection. Decoding it here means
// both implementations score against exactly the same bytes.
function loadCorpus() {
  const corpus = JSON.parse(readFileSync(join(BENCH, "corpus.json"), "utf8"));
  return Object.entries(corpus.files)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([path, encoded]) => ({
      path,
      content: Buffer.from(encoded, "base64").toString("utf8"),
    }));
}

const truth = JSON.parse(readFileSync(join(BENCH, "ground_truth.json"), "utf8"));
const files = loadCorpus();
const findings = files
  .filter((f) => isScannable(f.path))
  .flatMap((f) => scanFileForSecrets(f.path, f.content));

const TOLERANCE = truth.line_tolerance;

test("catches every planted secret the Python detector catches", () => {
  const planted = truth.planted.filter((p) => p.category === "secret");
  const missed = planted.filter(
    (p) =>
      !findings.some(
        (f) => f.file === p.file && Math.abs(f.line_start - p.line) <= TOLERANCE
      )
  );
  assert.deepEqual(missed.map((m) => `${m.file}:${m.line} ${m.why}`), []);
});

test("stays silent on every decoy", () => {
  // The half that matters: a scanner firing on AWS's documented sample key or
  // on `${TEMPLATE}` is one that gets muted within a day.
  const decoys = truth.decoys.filter((d) => d.category === "secret");
  const fired = decoys.filter((d) =>
    findings.some(
      (f) => f.file === d.file && Math.abs(f.line_start - d.line) <= TOLERANCE
    )
  );
  assert.deepEqual(fired.map((d) => `${d.file}:${d.line} ${d.why}`), []);
});

test("produces nothing in example or vendored files", () => {
  const decoyFiles = new Set(truth.decoy_files.map((d) => d.file));
  const fired = findings.filter((f) => decoyFiles.has(f.file));
  assert.deepEqual(fired.map((f) => `${f.file}:${f.line_start}`), []);
});

test("never returns the raw secret", () => {
  const raw = files.find((f) => f.path === "conf/settings.py").content;
  const serialised = JSON.stringify(findings);
  for (const f of findings) {
    assert.ok(f.evidence.includes("*"), `${f.rule_id} evidence is not redacted`);
  }
  // The planted AWS key must not survive anywhere in the output.
  const key = raw.match(/AKIA[A-Z0-9]{16}/g)?.find((k) => !k.includes("EXAMPLE"));
  if (key) assert.ok(!serialised.includes(key), "a raw secret reached the report");
});

test("entropy matches the Python implementation's behaviour", () => {
  assert.ok(shannonEntropy("hQ7zRt3XmW9pLd2VbN6cKfJ8sYaG4uEo") > 4.0);
  assert.ok(shannonEntropy("the quick brown fox") < 4.0);
  assert.equal(shannonEntropy(""), 0);
});

test("redaction keeps short values fully hidden", () => {
  assert.equal(redact("short"), "*****");
  assert.ok(redact("ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8").startsWith("ghp"));
});

test("placeholder detection catches the documented fakes", () => {
  assert.ok(isPlaceholder("AKIAIOSFODNN7EXAMPLE", ""));
  assert.ok(isPlaceholder("${VAULT_SECRET}", ""));
  assert.ok(isPlaceholder("<your-api-key>", ""));
  assert.ok(isPlaceholder("xxxxxxxxxxxxxxxx", ""));
  assert.ok(!isPlaceholder("hQ7zRt3XmW9pLd2VbN6cKfJ8sYaG4uEo", ""));
});

test("manifest parsing agrees with the Python parser", () => {
  const { packages, unpinned } = parseManifests(files);
  const names = packages.map((p) => `${p.name}@${p.version}`);
  // Same expectations as tests/test_deps_detector.py against this fixture.
  assert.ok(names.includes("requests@2.19.0"));
  assert.ok(names.includes("flask@0.12.2"));
  assert.ok(names.includes("pyyaml@5.1"));
  // An unpinned range must be reported, never resolved to a guess.
  assert.ok(unpinned.includes("urllib3"));
  assert.ok(!names.some((n) => n.startsWith("urllib3@")));
});

test("vendored manifests are ignored", () => {
  const { packages } = parseManifests([
    { path: "node_modules/x/package.json", content: '{"dependencies":{"a":"1.0.0"}}' },
  ]);
  assert.deepEqual(packages, []);
});

test("suppression rules behave like .secscanignore", () => {
  const rules = parseSuppressions("docs/**\ntests/**:github-pat\n:B101\n# comment\n");
  assert.equal(rules.length, 3);

  const sample = [
    { file: "docs/a.md", rule_id: "github-pat" },
    { file: "docs-internal/a.md", rule_id: "github-pat" },
    { file: "tests/t.py", rule_id: "github-pat" },
    { file: "src/t.py", rule_id: "github-pat" },
  ];
  const { kept, suppressed } = applySuppressions(sample, rules);
  assert.equal(suppressed, 2);
  // `docs/**` must not swallow `docs-internal/`.
  assert.deepEqual(kept.map((f) => f.file), ["docs-internal/a.md", "src/t.py"]);
});

test("aggregate dedupes and sorts like the CLI", () => {
  const report = aggregate(
    [
      { category: "secret", file: "a.py", line_start: 1, severity: "low", rule_id: "x", evidence: "e" },
      { category: "secret", file: "a.py", line_start: 1, severity: "high", rule_id: "y", evidence: "e" },
      { category: "secret", file: "b.py", line_start: 2, severity: "medium", rule_id: "z", evidence: "e" },
    ],
    { scannedFiles: 2, skippedFiles: 0, suppressed: 0, degraded: [] }
  );
  assert.equal(report.findings.length, 2);
  assert.equal(report.findings[0].severity, "high");
  assert.match(report.summary, /2 findings/);
});
