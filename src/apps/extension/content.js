// Adds a "Scan for secrets" button to GitHub repository pages, and reports
// progress on it while the service worker does the work.

(function () {
  // Top-level GitHub paths that are not repositories.
  const RESERVED = new Set([
    "settings", "marketplace", "notifications", "explore", "topics",
    "collections", "sponsors", "features", "about", "pricing", "login",
    "join", "new", "organizations", "dashboard", "search", "orgs", "apps",
    "codespaces", "account", "pulls", "issues", "watching", "stars",
  ]);

  const IDLE = "🛡️ Scan for secrets";

  function repoContext() {
    const parts = location.pathname.split("/").filter(Boolean);
    if (parts.length < 2) return null;
    const [owner, repo] = parts;
    if (RESERVED.has(owner.toLowerCase())) return null;
    // /tree/<branch>/... names a branch; otherwise resolve the default later.
    const ref = parts[2] === "tree" && parts[3] ? decodeURIComponent(parts[3]) : null;
    return { owner, repo, ref };
  }

  function button() {
    return document.getElementById("reposec-btn");
  }

  function setLabel(text, disabled) {
    const btn = button();
    if (!btn) return;
    btn.textContent = text;
    btn.disabled = !!disabled;
    btn.style.opacity = disabled ? "0.75" : "1";
    btn.style.cursor = disabled ? "default" : "pointer";
  }

  function reset(delay = 6000) {
    setTimeout(() => setLabel(IDLE, false), delay);
  }

  let scanning = false;

  async function onScan() {
    const ctx = repoContext();
    if (!ctx || scanning) return;
    scanning = true;
    setLabel("⏳ Starting…", true);
    try {
      const res = await chrome.runtime.sendMessage({ type: "scan", ...ctx });
      if (res && res.ok) {
        const n = res.report.findings.length;
        const high = res.report.counts_by_severity.high || 0;
        setLabel(
          n ? `${high ? "🚨" : "⚠️"} ${n} finding(s) — open popup` : "✅ No findings",
          false
        );
      } else {
        setLabel("⚠️ " + (res?.error?.message || "Scan failed"), false);
      }
    } catch (e) {
      setLabel("⚠️ " + (e.message || "Scan failed"), false);
    } finally {
      scanning = false;
      reset();
    }
  }

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "progress" && scanning) {
      setLabel(`⏳ ${msg.stage}${msg.detail ? " " + msg.detail : ""}…`, true);
    }
  });

  function addButton() {
    if (button() || !repoContext()) return;
    const btn = document.createElement("button");
    btn.id = "reposec-btn";
    btn.textContent = IDLE;
    btn.title = "Scan this repository for exposed secrets and vulnerable dependencies";
    Object.assign(btn.style, {
      position: "fixed", bottom: "20px", right: "20px", zIndex: "9999",
      padding: "10px 14px", background: "#1f6feb", color: "#fff", border: "none",
      borderRadius: "6px", cursor: "pointer", fontWeight: "600", fontSize: "13px",
      fontFamily: "-apple-system, Segoe UI, sans-serif",
      boxShadow: "0 2px 8px rgba(0,0,0,0.3)",
    });
    btn.addEventListener("click", onScan);
    document.body.appendChild(btn);
  }

  // GitHub navigates via pjax/turbo, so the button has to be re-added on DOM
  // changes rather than only on load.
  addButton();
  new MutationObserver(addButton).observe(document.body, {
    childList: true,
    subtree: true,
  });
})();
