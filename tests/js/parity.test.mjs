// Parity: the browser scanner must agree with the Python one.
//
// Two implementations of a secret rule set will drift, and a drifted scanner
// misses things exactly where nobody is looking. So this runs the JS detector
// over the same labelled benchmark fixture the Python detector scores against,
// and asserts the same planted findings and the same silence on the decoys.
//
// It scores rather than merely compares: `run_security_eval.py` reports
// precision/recall/F1 for the secret category and `tests/test_benchmark.py`
// puts a floor under them, so this file mirrors both. Comparing the rule table
// alone cannot see the drift that actually happened — the rules were identical
// while the suppression logic around them was not.
//
//     node --test tests/js/parity.test.mjs
//
// Run from the repo root.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

import {
  aggregate,
  applySuppressions,
  connectionStringVerdict,
  isPlaceholder,
  isScannable,
  parseManifests,
  parseSuppressions,
  redact,
  scanFileForSecrets,
  secretEntropy,
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

// --------------------------------------------------------------------------- //
// The score itself.
//
// The three tests above answer "did anything move". This answers the question
// CI actually needs answered: does the browser scanner earn the same number the
// CLI is published with? `run_security_eval.py` computes it as caught/missed
// against `planted` and false positives against `decoys` plus `decoy_files`,
// with `downgraded` scored apart as notes — a finding that must appear, but
// quietly. Reimplemented here rather than shelled out to, because the point is
// to measure *this* implementation with the *same* arithmetic.
// --------------------------------------------------------------------------- //
const SEVERITY_RANK = { high: 0, medium: 1, low: 2 };

function near(finding, entry) {
  return (
    finding.file === entry.file &&
    finding.category === entry.category &&
    Math.abs(finding.line_start - entry.line) <= TOLERANCE
  );
}

function scoreSecrets() {
  const caught = [];
  const missed = [];
  const falsePositives = [];
  const notes = [];

  for (const entry of truth.planted.filter((p) => p.category === "secret")) {
    const hit = findings.find(
      (f) => near(f, entry) && (!entry.rule_any || entry.rule_any.includes(f.rule_id))
    );
    const label = `${entry.file}:${entry.line} ${entry.why}`;
    (hit ? caught : missed).push(label);
    // Found but ranked below the floor: a detection success and a reporting
    // failure, and a scanner is only as useful as its ordering.
    if (hit && entry.expect_severity &&
        SEVERITY_RANK[hit.severity] > SEVERITY_RANK[entry.expect_severity]) {
      notes.push(
        `${label} was found but ranked '${hit.severity}', below the expected ` +
        `'${entry.expect_severity}'`
      );
    }
  }

  for (const entry of truth.decoys.filter((d) => d.category === "secret")) {
    const hit = findings.find((f) => near(f, entry));
    if (hit) {
      const known = entry.known_failure ? ` [known: ${entry.known_failure}]` : "";
      falsePositives.push(
        `${entry.file}:${entry.line} fired ${hit.rule_id} — ${entry.why}${known}`
      );
    }
  }

  // The mirror image: these must fire, and must not shout.
  for (const entry of (truth.downgraded || []).filter((d) => d.category === "secret")) {
    const hit = findings.find((f) => near(f, entry));
    if (!hit) {
      notes.push(
        `${entry.file}:${entry.line} produced no finding at all — expected one, ` +
        `ranked no higher than '${entry.max_severity}'`
      );
    } else if (SEVERITY_RANK[hit.severity] < SEVERITY_RANK[entry.max_severity]) {
      notes.push(
        `${entry.file}:${entry.line} was ranked '${hit.severity}', above the ` +
        `'${entry.max_severity}' ceiling for ${entry.why}`
      );
    }
  }

  // A finding anywhere in a decoy file is a false positive by definition.
  for (const entry of truth.decoy_files) {
    for (const f of findings.filter((f) => f.file === entry.file)) {
      falsePositives.push(`${f.file}:${f.line_start} fired ${f.rule_id} — ${entry.why}`);
    }
  }

  const recall = caught.length / (caught.length + missed.length || 1);
  const fired = caught.length + falsePositives.length;
  const precision = fired ? caught.length / fired : 0;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  return { caught, missed, falsePositives, notes, precision, recall, f1 };
}

const score = scoreSecrets();

test("scores the same as the Python secret detector on the labelled benchmark", () => {
  // Printed in the same shape as run_security_eval.py's summary, so a CI log
  // shows the number rather than only whether it cleared the bar.
  console.log(
    `  secrets (js)   P ${score.precision.toFixed(2)}   R ${score.recall.toFixed(2)}   ` +
    `F1 ${score.f1.toFixed(2)}    caught ${score.caught.length}  ` +
    `missed ${score.missed.length}  FP ${score.falsePositives.length}`
  );

  // The same floors as tests/test_benchmark.py::test_secret_detector_holds_its_score.
  // Precision is the binding constraint: a secret scanner that cries wolf on
  // driver documentation gets muted within a day, and the browser is the copy
  // most likely to be pointed at somebody else's repository.
  assert.ok(score.recall >= 0.95, `missed planted secrets: ${score.missed}`);
  assert.equal(score.precision, 1.0, `false positives on decoys: ${score.falsePositives}`);
});

test("ranks findings where the benchmark says they belong", () => {
  // Severity is not scored into precision, so without this a regression that
  // reports every real credential as 'low' would still show F1 1.00.
  assert.deepEqual(score.notes, []);
});

test("scores every labelled secret case, so the fixture cannot grow past it", () => {
  // Guards the scorer itself: if the JS scanner ever stopped producing secret
  // findings entirely, precision would be 0/0 and the assertions above would
  // need this to notice.
  const planted = truth.planted.filter((p) => p.category === "secret").length;
  assert.equal(score.caught.length + score.missed.length, planted);
  assert.ok(planted > 0);
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

// --------------------------------------------------------------------------- //
// Documentation handling must match `detectors/secrets.py`. The two
// implementations drifted here once already — the browser reported Flask's doc
// examples at full severity while the CLI downgraded them.
// --------------------------------------------------------------------------- //
const HIGH_ENTROPY = "hQ7zRt3XmW9pLd2Vb" + "N6cKfJ8sYaG4uEo";
const DOC_PAT = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";

test("entropy findings in docs are downgraded, not dropped", () => {
  const found = scanFileForSecrets("docs/config.rst", `SECRET_KEY = "${HIGH_ENTROPY}"`);
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, "low");
  assert.equal(found[0].detector_severity, "medium");
  assert.match(found[0].explanation, /documentation file/);
});

test("a provider token in docs keeps its severity", () => {
  const found = scanFileForSecrets("docs/guide.md", `token = "${DOC_PAT}"`);
  assert.equal(found[0].severity, "high");
  assert.doesNotMatch(found[0].explanation, /documentation file/);
});

test("ordinary source is not downgraded", () => {
  const found = scanFileForSecrets("app/config.py", `API_KEY = "${HIGH_ENTROPY}"`);
  assert.equal(found[0].severity, "medium");
});

// --------------------------------------------------------------------------- //
// Connection strings and segment-wise entropy — the two suppression rules that
// drifted. Unit-level assertions alongside the benchmark score, because the
// fixture carries one example of each shape and these carry the boundaries.
// Every expectation here is read off `_connection_string_verdict` and
// `_secret_entropy` in `detectors/secrets.py`.
// --------------------------------------------------------------------------- //
test("connection-string verdicts match _connection_string_verdict", () => {
  // Illustrative password, whatever the host.
  assert.equal(connectionStringVerdict("postgresql://scott:tiger@db.acme.io/prod"), "drop");
  assert.equal(connectionStringVerdict("mysql://user:password@10.0.0.4/app"), "drop");
  // Password equal to the username is a docstring, not a credential.
  assert.equal(connectionStringVerdict("redis://alice:alice@cache.acme.io:6379/0"), "drop");
  // Templates in the password slot.
  assert.equal(connectionStringVerdict("postgres://svc:${PGPASSWORD}@db.acme.io/prod"), "drop");
  assert.equal(connectionStringVerdict("postgres://svc:%(password)s@db.acme.io/prod"), "drop");
  // Illustrative host, including the RFC 2606 reserved domains and .local.
  assert.equal(connectionStringVerdict("postgres://svc:Xk7pQ2ma@localhost/prod"), "drop");
  assert.equal(connectionStringVerdict("postgres://svc:Xk7pQ2ma@example.com/prod"), "drop");
  assert.equal(connectionStringVerdict("postgres://svc:Xk7pQ2ma@db.local/prod"), "drop");
  // Private ranges are a developer's own network: real, but not the
  // internet-reachable data access the rule's 'high' is describing.
  assert.equal(connectionStringVerdict("postgres://svc:Xk7pQ2ma@192.168.4.7:5432/prod"), "downgrade");
  assert.equal(connectionStringVerdict("postgres://svc:Xk7pQ2ma@172.16.9.1/prod"), "downgrade");
  // 172.32 is outside RFC 1918 and must not be caught by the /12 boundary.
  assert.equal(connectionStringVerdict("postgres://svc:Xk7pQ2ma@172.32.9.1/prod"), "keep");
  assert.equal(connectionStringVerdict("postgres://svc:Xk7pQ2ma@db.acme.io/prod"), "keep");
  // Not a connection string at all.
  assert.equal(connectionStringVerdict("ghp_A1b2C3d4"), "keep");
});

test("a private-host connection string is downgraded and says why", () => {
  const found = scanFileForSecrets(
    "app/settings.py",
    'DB = "postgresql://svc:Xk7pQ2ma@192.168.4.7:5432/prod"'
  );
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, "medium");
  assert.equal(found[0].detector_severity, "high");
  assert.match(found[0].explanation, /private network/);
});

test("a routable connection string with a real password still fires high", () => {
  const found = scanFileForSecrets(
    "app/settings.py",
    'DB = "postgresql://svc:Xk7pQ2ma@db.acme.io:5432/prod"'
  );
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, "high");
});

// The floor on the rules these two decoys are matched by. Both clear it when
// measured across the whole string and fail it segment by segment; that gap is
// the entire mechanism.
const KEY_RULE_FLOOR = 3.6;

test("entropy is measured per segment, not across separators", () => {
  for (const structured of ["AES/CBC/PKCS5Padding", "django.core.signing.TimestampSigner"]) {
    assert.ok(
      shannonEntropy(structured) >= KEY_RULE_FLOOR,
      `${structured} is supposed to clear the floor whole — otherwise this test proves nothing`
    );
    assert.ok(secretEntropy(structured) < KEY_RULE_FLOOR, `${structured} still clears the floor`);
  }
  // A JWT is separator-heavy and genuinely random: each section survives.
  assert.ok(secretEntropy("hQ7zRt3XmW9pLd2Vb.N6cKfJ8sYaG4uEo.Zq1wS5xT") > 4.0);
  // No separator: identical to the whole-string measure.
  const flat = "hQ7zRt3XmW9pLd2VbN6cKfJ8sYaG4uEo";
  assert.equal(secretEntropy(flat), shannonEntropy(flat));
});

// --------------------------------------------------------------------------- //
// The regression this file exists for.
//
// Every line below is a connection string lifted verbatim from the SQLAlchemy
// dialect docstrings installed in this project's own environment — the exact
// strings that produced 14 secret "findings" from the browser scanner over the
// 428 kLOC real-code corpus while the CLI reported none. They are documentation
// of a URL format; not one of them is a credential.
// --------------------------------------------------------------------------- //
const SQLALCHEMY_DOCSTRINGS = [
  "mysql+pymysql://user:pass@some_mariadb/dbname?charset=utf8mb4",
  "mysql://user:pass@some_mariadb/dbname?charset=utf8mb4",
  "mysql+mysqldb://scott:tiger@localhost/test",
  "mysql+pymysql://scott:tiger@localhost/test?charset=utf8mb4",
  "mysql+mysqldb://scott:tiger@localhost/test?charset=utf8mb4&binary_prefix=true",
  "mysql+mysqldb://scott:tiger@hostname/dbname",
  "postgresql://scott:tiger@localhost/test",
  "postgresql+psycopg2://scott:tiger@localhost/test",
  "postgresql+psycopg2://scott:tiger@192.168.0.199:5432/test?sslmode=require",
  "postgresql+psycopg2://scott:tiger@host/dbname",
  "postgresql+psycopg2://user:password@myhost1/dbname?host=myhost2",
  "postgresql+psycopg2://user:pass@host/dbname?client_encoding=utf8",
  "postgresql+asyncpg://user:pass@hostname/dbname?prepared_statement_cache_size=500",
  "postgresql+asyncpg://user:pass@somepgbouncer/dbname",
  "postgresql+asyncpg://user:password@localhost/tmp",
  "mysql+aiomysql://user:pass@hostname/dbname?charset=utf8mb4",
];

test("SQLAlchemy's documented connection strings produce nothing", () => {
  const content = SQLALCHEMY_DOCSTRINGS.map((url) => `    e = create_engine("${url}")`).join("\n");
  const found = scanFileForSecrets("thirdparty/sqlalchemy/dialects/base.py", content);
  assert.deepEqual(
    found.map((f) => `${f.line_start}: ${SQLALCHEMY_DOCSTRINGS[f.line_start - 1]}`),
    []
  );
});
