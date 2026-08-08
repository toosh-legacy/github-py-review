// End-to-end exercise of the extension's scan path against live GitHub + OSV.
//
//     node tests/js/extension.e2e.mjs [owner/repo]
//
// Not part of `node --test`: it needs the network, and a test suite that fails
// when GitHub rate-limits is a test suite people learn to ignore. This is the
// harness for checking the real thing by hand, and for CI on a schedule.
//
// It stubs the four Chrome APIs the service worker touches and then drives the
// same message it would receive from the content script, so everything below
// that message is the shipped code path: the tree API, the raw-content worker
// pool, both detectors, suppression, and aggregation.

const messages = [];
const storage = {};

globalThis.chrome = {
  storage: {
    local: {
      async get(keys) {
        const wanted = typeof keys === "string" ? [keys] : keys;
        return Object.fromEntries(
          wanted.filter((k) => k in storage).map((k) => [k, storage[k]])
        );
      },
      async set(items) {
        Object.assign(storage, items);
      },
    },
  },
  tabs: {
    async sendMessage(_tabId, msg) {
      if (msg.type === "progress") {
        const line = `  ${msg.stage}${msg.detail ? " " + msg.detail : ""}`;
        // Progress is noisy by design; only show it changing stage.
        if (messages.at(-1) !== msg.stage) process.stdout.write(line + "\n");
        messages.push(msg.stage);
      }
    },
  },
  runtime: { onMessage: { addListener: (fn) => (globalThis.__listener = fn) } },
  action: { setBadgeText() {}, setBadgeBackgroundColor() {} },
};

// A token lifts the anonymous rate limit, which a tree listing plus a few
// hundred raw fetches will otherwise hit.
if (process.env.GITHUB_TOKEN) storage.ghToken = process.env.GITHUB_TOKEN;

await import("../../src/apps/extension/background.js");

const [owner, repo] = (process.argv[2] || "pallets/flask").split("/");
console.log(`scanning ${owner}/${repo} — no backend, everything in-process\n`);

const started = Date.now();
const result = await new Promise((resolve) => {
  globalThis.__listener(
    { type: "scan", owner, repo, ref: null },
    { tab: { id: 1 } },
    resolve
  );
});

if (!result.ok) {
  console.error(`\nFAILED: ${result.error.message}`);
  process.exit(1);
}

const r = result.report;
console.log(`\n${r.summary}`);
console.log(`${r.scanned_files} files scanned, ${r.suppressed} suppressed`);
for (const note of r.degraded) console.log(`  ! ${note}`);

console.log("");
for (const f of r.findings.slice(0, 12)) {
  const where = f.line_start ? `${f.file}:${f.line_start}` : f.file;
  console.log(`  ${f.severity.padEnd(6)} ${f.category.padEnd(11)} ${f.rule_id.padEnd(22)} ${where}`);
}
if (r.findings.length > 12) console.log(`  … and ${r.findings.length - 12} more`);

// The invariants that matter, asserted rather than eyeballed.
const problems = [];
if (!r.degraded.some((d) => d.startsWith("code:"))) {
  problems.push("the missing code detector was not disclosed");
}
for (const f of r.findings) {
  if (f.category === "secret" && !f.evidence.includes("*")) {
    problems.push(`unredacted evidence on ${f.rule_id}`);
  }
  if (f.category === "code") {
    problems.push("the browser cannot run code analysis but reported a code finding");
  }
}
if (!storage.lastScan) problems.push("the report was not persisted for the popup");

console.log(`\ncompleted in ${((Date.now() - started) / 1000).toFixed(1)}s`);
if (problems.length) {
  console.error("\nPROBLEMS:");
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}
console.log("all invariants hold");
