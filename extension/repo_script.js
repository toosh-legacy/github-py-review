// Adds a "Scan & Debug file" button to GitHub repo pages. It lists the repo's
// Python files (GitHub REST API), lets you pick one, fetches its raw content,
// and hands it to the background worker, which calls the backend's /debug/file.
// Results show in the toolbar popup — same as the PR flow.

(function () {
  // Top-level GitHub paths that are not repositories.
  const RESERVED = new Set([
    "settings", "marketplace", "notifications", "explore", "topics",
    "collections", "sponsors", "features", "about", "pricing", "login",
    "join", "new", "organizations", "dashboard", "search", "orgs", "apps",
    "codespaces", "account", "pulls", "issues", "watching", "stars",
  ]);

  // { owner, repo, branch|null } for a repo page, else null. `branch` comes from
  // /tree/<branch>/... when present; otherwise we resolve the default later.
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

  async function listPythonFiles(ctx, branch) {
    const tree = await ghFetch(
      `https://api.github.com/repos/${ctx.owner}/${ctx.repo}/git/trees/${branch}?recursive=1`
    );
    return (tree.tree || [])
      .filter((n) => n.type === "blob" && n.path.endsWith(".py"))
      .map((n) => n.path);
  }

  async function rawContent(ctx, branch, path) {
    const url = `https://raw.githubusercontent.com/${ctx.owner}/${ctx.repo}/${branch}/${path}`;
    const r = await fetch(url);
    if (!r.ok) throw new Error(`Could not fetch ${path} (${r.status})`);
    return r.text();
  }

  // ----- UI ---------------------------------------------------------------- //
  function addButton() {
    if (document.getElementById("crc-scan-btn") || !repoContext()) return;
    const btn = document.createElement("button");
    btn.id = "crc-scan-btn";
    btn.textContent = "🔎 Scan & Debug file";
    Object.assign(btn.style, {
      position: "fixed", bottom: "20px", right: "20px", zIndex: "9999",
      padding: "10px 14px", background: "#8250df", color: "#fff", border: "none",
      borderRadius: "6px", cursor: "pointer", fontWeight: "600",
      boxShadow: "0 2px 8px rgba(0,0,0,0.3)",
    });
    btn.addEventListener("click", onScan);
    document.body.appendChild(btn);
  }

  function closePanel() {
    document.getElementById("crc-panel")?.remove();
  }

  function showPicker(ctx, branch, files) {
    closePanel();
    const panel = document.createElement("div");
    panel.id = "crc-panel";
    Object.assign(panel.style, {
      position: "fixed", bottom: "70px", right: "20px", zIndex: "10000",
      width: "380px", maxHeight: "60vh", display: "flex", flexDirection: "column",
      background: "#fff", color: "#1f2328", border: "1px solid #d0d7de",
      borderRadius: "8px", boxShadow: "0 8px 24px rgba(0,0,0,0.2)",
      fontFamily: "-apple-system, Segoe UI, sans-serif", overflow: "hidden",
    });

    const header = document.createElement("div");
    header.style.cssText =
      "padding:8px 10px;font-weight:600;border-bottom:1px solid #d0d7de;display:flex;justify-content:space-between;align-items:center;";
    header.innerHTML = `<span>Pick a file to debug (${files.length} .py)</span>`;
    const close = document.createElement("button");
    close.textContent = "✕";
    close.style.cssText = "border:none;background:none;cursor:pointer;font-size:14px;";
    close.addEventListener("click", closePanel);
    header.appendChild(close);

    const filter = document.createElement("input");
    filter.placeholder = "Filter files…";
    filter.style.cssText =
      "margin:8px 10px;padding:6px 8px;border:1px solid #d0d7de;border-radius:6px;";

    const list = document.createElement("div");
    list.style.cssText = "overflow:auto;padding:4px 6px;";

    function renderList(items) {
      list.innerHTML = "";
      for (const path of items.slice(0, 500)) {
        const row = document.createElement("div");
        row.textContent = path;
        row.title = path;
        row.style.cssText =
          "padding:6px 8px;border-radius:6px;cursor:pointer;font-size:13px;font-family:monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;";
        row.addEventListener("mouseenter", () => (row.style.background = "#f3f0ff"));
        row.addEventListener("mouseleave", () => (row.style.background = ""));
        row.addEventListener("click", () => pickFile(ctx, branch, path));
        list.appendChild(row);
      }
    }
    filter.addEventListener("input", () => {
      const q = filter.value.toLowerCase();
      renderList(files.filter((f) => f.toLowerCase().includes(q)));
    });
    renderList(files);

    panel.append(header, filter, list);
    document.body.appendChild(panel);
    filter.focus();
  }

  function setButton(text, disabled) {
    const btn = document.getElementById("crc-scan-btn");
    if (!btn) return;
    btn.textContent = text;
    btn.disabled = !!disabled;
  }

  async function onScan() {
    const ctx = repoContext();
    if (!ctx) return;
    setButton("⏳ Scanning…", true);
    try {
      const branch = await resolveBranch(ctx);
      const files = await listPythonFiles(ctx, branch);
      if (!files.length) {
        setButton("No .py files found", false);
        setTimeout(() => setButton("🔎 Scan & Debug file", false), 4000);
        return;
      }
      showPicker(ctx, branch, files);
      setButton("🔎 Scan & Debug file", false);
    } catch (e) {
      setButton("⚠️ " + (e.message || "Scan failed"), false);
      setTimeout(() => setButton("🔎 Scan & Debug file", false), 6000);
    }
  }

  async function pickFile(ctx, branch, path) {
    closePanel();
    setButton(`⏳ Debugging ${path}…`, true);
    try {
      const content = await rawContent(ctx, branch, path);
      const res = await chrome.runtime.sendMessage({
        type: "debug",
        path,
        content,
        repo: `${ctx.owner}/${ctx.repo}`,
      });
      if (res && res.ok) {
        const n = (res.report.report || res.report).issues.length;
        setButton(`✅ ${n} finding(s) — open popup`, false);
      } else {
        setButton("⚠️ Error — open popup", false);
      }
    } catch (e) {
      setButton("⚠️ " + (e.message || "Failed"), false);
    } finally {
      setTimeout(() => setButton("🔎 Scan & Debug file", false), 6000);
    }
  }

  // GitHub navigates via pjax/turbo; re-add the button on DOM changes.
  addButton();
  new MutationObserver(addButton).observe(document.body, {
    childList: true,
    subtree: true,
  });
})();
