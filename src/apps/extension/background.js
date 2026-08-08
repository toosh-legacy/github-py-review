// Service worker: fetches a repository's files and scans them here.
//
// The scan runs in this worker rather than in the page, because it is the only
// context that survives navigation and can hold the GitHub token. Nothing is
// posted to a server: `scanner.js` does the work, and the only outbound request
// the scan itself makes is to OSV, carrying package names and versions.

import {
  aggregate,
  applySuppressions,
  isScannable,
  parseSuppressions,
  scanDependencies,
  scanFileForSecrets,
} from "./scanner.js";

// Guardrails. Without them a monorepo means thousands of raw fetches and a
// rate-limit ban halfway through.
const MAX_FILES = 600;
const MAX_FILE_BYTES = 400 * 1024;
const MAX_TOTAL_BYTES = 12 * 1024 * 1024;
const CONCURRENCY = 8;

// Exact filenames worth scanning regardless of extension.
const FILENAMES = new Set([
  ".secscanignore",
  "dockerfile", "docker-compose.yml", "docker-compose.yaml", "makefile",
  "procfile", "package.json", "package-lock.json", "yarn.lock",
  "pnpm-lock.yaml", "pipfile", "pipfile.lock", "pyproject.toml",
  "poetry.lock", "gemfile", "gemfile.lock", "go.mod", "go.sum",
]);

// Secrets hide in CI configs, Terraform and shell scripts far more often than
// in .py files, so this is deliberately wider than "source code".
const EXTENSIONS = new Set([
  "py", "pyi", "js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts",
  "json", "yml", "yaml", "toml", "ini", "cfg", "conf", "properties",
  "env", "sh", "bash", "zsh", "ps1", "tf", "tfvars", "hcl",
  "txt", "md", "xml", "gradle", "rb", "php", "java", "go", "rs",
  "pem", "key", "crt", "sql",
]);

async function ghToken() {
  const { ghToken } = await chrome.storage.local.get("ghToken");
  return ghToken || null;
}

async function ghFetch(url) {
  const headers = { Accept: "application/vnd.github+json" };
  const token = await ghToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  const r = await fetch(url, { headers });
  if (r.status === 403 || r.status === 429) {
    throw new Error("GitHub API rate limit hit. Add a token in the popup to raise it.");
  }
  if (r.status === 404) {
    throw new Error("Repository not found, or it is private and the token cannot see it.");
  }
  if (!r.ok) throw new Error(`GitHub API ${r.status}`);
  return r.json();
}

function wanted(path) {
  if (!isScannable(path)) return false;
  const name = path.split("/").pop().toLowerCase();
  if (FILENAMES.has(name)) return true;
  if (name.startsWith(".env")) return true;
  const dot = name.lastIndexOf(".");
  return dot !== -1 && EXTENSIONS.has(name.slice(dot + 1));
}

// Manifests and configs first, so a truncated monorepo still yields a dependency
// check and still covers the likeliest hiding places for a credential.
function priority(path) {
  const name = path.split("/").pop().toLowerCase();
  if (FILENAMES.has(name) || name.startsWith(".env")) return 0;
  if (/\.(ya?ml|toml|ini|cfg|conf|tf|tfvars|sh|ps1|properties)$/.test(name)) return 1;
  return 2;
}

function selectFiles(tree) {
  const blobs = (tree.tree || []).filter(
    (n) => n.type === "blob" && wanted(n.path) && (n.size || 0) <= MAX_FILE_BYTES
  );
  blobs.sort((a, b) => priority(a.path) - priority(b.path) || a.path.localeCompare(b.path));

  const chosen = [];
  let total = 0;
  for (const node of blobs) {
    if (chosen.length >= MAX_FILES || total + (node.size || 0) > MAX_TOTAL_BYTES) break;
    chosen.push(node.path);
    total += node.size || 0;
  }
  return { paths: chosen, truncated: chosen.length < blobs.length };
}

// A bounded worker pool: GitHub throttles bursts, and 600 simultaneous requests
// is a good way to get rate limited mid-scan.
async function fetchAll(owner, repo, ref, paths, onProgress) {
  const files = [];
  let index = 0;
  let done = 0;

  async function worker() {
    while (index < paths.length) {
      const path = paths[index++];
      try {
        const r = await fetch(
          `https://raw.githubusercontent.com/${owner}/${repo}/${ref}/${encodeURI(path)}`
        );
        if (r.ok) files.push({ path, content: await r.text() });
      } catch { /* one unreadable file must not lose the scan */ }
      onProgress(++done, paths.length);
    }
  }
  await Promise.all(
    Array.from({ length: Math.min(CONCURRENCY, paths.length) }, worker)
  );
  return files;
}

async function runScan({ owner, repo, ref }, tabId) {
  const progress = (stage, detail) => {
    chrome.tabs.sendMessage(tabId, { type: "progress", stage, detail }).catch(() => {});
  };

  progress("Resolving branch");
  const resolvedRef = ref || (await ghFetch(`https://api.github.com/repos/${owner}/${repo}`)).default_branch || "main";

  progress("Listing files");
  const tree = await ghFetch(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${resolvedRef}?recursive=1`
  );
  const { paths, truncated } = selectFiles(tree);
  if (!paths.length) throw new Error("No scannable files found in this repository.");

  const files = await fetchAll(owner, repo, resolvedRef, paths, (done, total) =>
    progress("Fetching", `${done}/${total}`)
  );

  progress("Scanning");
  const secretFindings = files.flatMap((f) => scanFileForSecrets(f.path, f.content));

  progress("Checking dependencies");
  const { findings: depFindings, degraded } = await scanDependencies(files);

  const suppression = files.find((f) => f.path.split("/").pop() === ".secscanignore");
  const rules = suppression ? parseSuppressions(suppression.content) : [];
  const { kept, suppressed } = applySuppressions(
    [...secretFindings, ...depFindings],
    rules
  );

  const notes = [...degraded];
  // Never let a partial scan read as a clean one.
  notes.push(
    "code: unsafe-code analysis (bandit, eslint-plugin-security) needs a local " +
      "process and is not available in the browser — run `reposec scan` for it"
  );
  if (truncated) {
    notes.push(
      `scope: repository is larger than the ${MAX_FILES}-file cap; only the ` +
        "highest-priority files were scanned"
    );
  }

  return {
    ...aggregate(kept, {
      scannedFiles: files.length,
      skippedFiles: paths.length - files.length,
      suppressed,
      degraded: notes,
    }),
    repo: `${owner}/${repo}`,
    ref: resolvedRef,
    scannedAt: new Date().toISOString(),
  };
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type !== "scan") return;
  (async () => {
    try {
      const report = await runScan(msg, sender.tab?.id);
      await chrome.storage.local.set({ lastScan: report });
      const high = report.counts_by_severity.high || 0;
      chrome.action.setBadgeText({ text: String(report.findings.length) });
      chrome.action.setBadgeBackgroundColor({ color: high ? "#cf222e" : "#1f6feb" });
      sendResponse({ ok: true, report });
    } catch (e) {
      const error = { message: e.message || String(e) };
      await chrome.storage.local.set({ lastScan: { error } });
      chrome.action.setBadgeText({ text: "!" });
      chrome.action.setBadgeBackgroundColor({ color: "#cf222e" });
      sendResponse({ ok: false, error });
    }
  })();
  return true; // keep the message channel open for the async response
});
