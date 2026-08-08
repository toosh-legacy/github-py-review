// Adds a "Security scan" button to GitHub repository pages.
//
// Collects the repo's scannable files (GitHub REST API for the tree, raw.
// githubusercontent for contents) and posts them to the backend, which runs the
// three detectors — secret rules, OSV dependency lookup, bandit/eslint — and
// then has the LLM triage the results. Findings render in the toolbar popup.
//
// The selection below is deliberately wider than "source code": secrets hide in
// CI configs, Terraform, shell scripts and .env files far more often than in
// .py files, and the dependency detector needs the manifests.

(function () {
  // Top-level GitHub paths that are not repositories.
  const RESERVED = new Set([
    "settings", "marketplace", "notifications", "explore", "topics",
    "collections", "sponsors", "features", "about", "pricing", "login",
    "join", "new", "organizations", "dashboard", "search", "orgs", "apps",
    "codespaces", "account", "pulls", "issues", "watching", "stars",
  ]);

  // Exact filenames worth scanning regardless of extension.
  const FILENAMES = new Set([
    "dockerfile", "docker-compose.yml", "docker-compose.yaml", "makefile",
    "procfile", "package.json", "package-lock.json", "yarn.lock",
    "pnpm-lock.yaml", "pipfile", "pipfile.lock", "pyproject.toml",
    "poetry.lock", "gemfile", "gemfile.lock", "go.mod", "go.sum",
  ]);

  // Extensions worth scanning: code the linters understand, plus the config
  // and script formats where credentials actually get committed.
  const EXTENSIONS = new Set([
    "py", "pyi", "js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts",
    "json", "yml", "yaml", "toml", "ini", "cfg", "conf", "properties",
    "env", "sh", "bash", "zsh", "ps1", "tf", "tfvars", "hcl",
    "txt", "md", "xml", "gradle", "rb", "php", "java", "go", "rs",
    "pem", "key", "crt", "p12", "pfx", "sql",
  ]);

  // Directories whose contents are not the user's code (or are generated).
  const SKIP_DIRS = new Set([
    "node_modules", "vendor", "third_party", "bower_components", ".venv",
    "venv", "env", "site-packages", "dist", "build", "target", "out",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".tox", "coverage",
    ".next", ".nuxt", ".git",
  ]);

  // Guardrails. A monorepo would otherwise mean thousands of raw fetches and a
  // payload the backend rejects anyway.
  const MAX_FILES = 600;
  const MAX_FILE_BYTES = 400 * 1024;
  const MAX_TOTAL_BYTES = 12 * 1024 * 1024;
  const CONCURRENCY = 8;

  function repoContext() {
    if (/\/pull\/\d+/.test(location.pathname)) return null; // PR flow owns those
    const parts = location.pathname.split("/").filter(Boolean);
    if (parts.length < 2) return null;
    const [owner, repo] = parts;
    if (RESERVED.has(owner.toLowerCase())) return null;
    let branch = null;
    if (parts[2] === "tree" && parts[3]) branch = decodeURIComponent(parts[3]);
    return { owner, repo, branch };
  }

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
      throw new Error(
        "GitHub API rate limit hit. Add a token in the popup to raise it."
      );
    }
    if (!r.ok) throw new Error(`GitHub API ${r.status} for ${url}`);
    return r.json();
  }

  async function resolveBranch(ctx) {
    if (ctx.branch) return ctx.branch;
    const info = await ghFetch(
      `https://api.github.com/repos/${ctx.owner}/${ctx.repo}`
    );
    return info.default_branch || "main";
  }

  function isScannable(path) {
    const segments = path.split("/");
    if (segments.some((s) => SKIP_DIRS.has(s))) return false;
    const name = segments[segments.length - 1].toLowerCase();
    if (name.endsWith(".min.js") || name.endsWith(".min.css")) return false;
    if (FILENAMES.has(name)) return true;
    if (name.startsWith(".env")) return true;
    const dot = name.lastIndexOf(".");
    if (dot === -1) return false;
    return EXTENSIONS.has(name.slice(dot + 1));
  }

  // Which files to send, in priority order — manifests and config first so that
  // if the cap truncates a huge repo, the dependency detector still has its
  // inputs and the secret rules still see the likeliest hiding places.
  function selectFiles(tree) {
    const blobs = (tree.tree || []).filter(
      (n) => n.type === "blob" && isScannable(n.path) && (n.size || 0) <= MAX_FILE_BYTES
    );
    const rank = (path) => {
      const name = path.split("/").pop().toLowerCase();
      if (FILENAMES.has(name) || name.startsWith(".env")) return 0;
      if (/\.(ya?ml|toml|ini|cfg|conf|tf|tfvars|sh|ps1|properties)$/.test(name)) return 1;
      return 2;
    };
    blobs.sort((a, b) => rank(a.path) - rank(b.path) || a.path.localeCompare(b.path));

    const chosen = [];
    let total = 0;
    for (const node of blobs) {
      if (chosen.length >= MAX_FILES || total + (node.size || 0) > MAX_TOTAL_BYTES) break;
      chosen.push(node.path);
      total += node.size || 0;
    }
    return { paths: chosen, truncated: chosen.length < blobs.length };
  }

  async function rawContent(ctx, branch, path) {
    const url = `https://raw.githubusercontent.com/${ctx.owner}/${ctx.repo}/${branch}/${encodeURI(path)}`;
    const r = await fetch(url);
    if (!r.ok) return null;
    return r.text();
  }

  // Fetch with a bounded worker pool: GitHub throttles bursts, and a repo of
  // 600 simultaneous requests is a good way to get rate limited mid-scan.
  async function fetchAll(ctx, branch, paths, onProgress) {
    const files = [];
    let index = 0;
    let done = 0;
    async function worker() {
      while (index < paths.length) {
        const path = paths[index++];
        const content = await rawContent(ctx, branch, path).catch(() => null);
        if (content !== null) files.push({ path, content });
        onProgress(++done, paths.length);
      }
    }
    await Promise.all(
      Array.from({ length: Math.min(CONCURRENCY, paths.length) }, worker)
    );
    return files;
  }

  // ----- UI ---------------------------------------------------------------- //
  function addButton() {
    if (document.getElementById("crc-scan-btn") || !repoContext()) return;
    const btn = document.createElement("button");
    btn.id = "crc-scan-btn";
    btn.textContent = "🛡️ Security scan";
    Object.assign(btn.style, {
      position: "fixed", bottom: "20px", right: "20px", zIndex: "9999",
      padding: "10px 14px", background: "#1f6feb", color: "#fff", border: "none",
      borderRadius: "6px", cursor: "pointer", fontWeight: "600",
      boxShadow: "0 2px 8px rgba(0,0,0,0.3)",
    });
    btn.addEventListener("click", onScan);
    document.body.appendChild(btn);
  }

  function setButton(text, disabled) {
    const btn = document.getElementById("crc-scan-btn");
    if (!btn) return;
    btn.textContent = text;
    btn.disabled = !!disabled;
  }

  function reset(delay = 6000) {
    setTimeout(() => setButton("🛡️ Security scan", false), delay);
  }

  let scanning = false;

  async function onScan() {
    const ctx = repoContext();
    if (!ctx || scanning) return;
    scanning = true;
    setButton("⏳ Listing files…", true);
    try {
      const branch = await resolveBranch(ctx);
      const tree = await ghFetch(
        `https://api.github.com/repos/${ctx.owner}/${ctx.repo}/git/trees/${branch}?recursive=1`
      );
      const { paths, truncated } = selectFiles(tree);
      if (!paths.length) {
        setButton("No scannable files found", false);
        reset(4000);
        return;
      }

      const files = await fetchAll(ctx, branch, paths, (done, total) =>
        setButton(`⏳ Fetching ${done}/${total}…`, true)
      );

      setButton(`🔍 Scanning ${files.length} files…`, true);
      const res = await chrome.runtime.sendMessage({
        type: "security",
        repo: `${ctx.owner}/${ctx.repo}`,
        ref: branch,
        files,
        truncated,
      });

      if (res && res.ok) {
        const report = res.report.report || res.report;
        const high = (report.counts_by_severity || {}).high || 0;
        const n = report.findings.length;
        setButton(
          n ? `${high ? "🚨" : "⚠️"} ${n} finding(s) — open popup` : "✅ No findings",
          false
        );
      } else {
        setButton("⚠️ Error — open popup", false);
      }
    } catch (e) {
      setButton("⚠️ " + (e.message || "Scan failed"), false);
    } finally {
      scanning = false;
      reset();
    }
  }

  // GitHub navigates via pjax/turbo; re-add the button on DOM changes.
  addButton();
  new MutationObserver(addButton).observe(document.body, {
    childList: true,
    subtree: true,
  });
})();
