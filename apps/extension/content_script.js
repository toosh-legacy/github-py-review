// Adds a floating "Review this PR" button to GitHub pull-request pages.
// On click it grabs the PR's unified diff (same-origin `<pr>.diff`) and hands
// it to the background worker, which calls the backend. Results are shown in
// the toolbar popup.

(function () {
  const PR_RE = /^(https:\/\/github\.com\/[^/]+\/[^/]+\/pull\/\d+)/;

  function prBaseUrl() {
    const m = PR_RE.exec(window.location.href);
    return m ? m[1] : null;
  }

  function addButton() {
    if (document.getElementById("crc-review-btn") || !prBaseUrl()) return;
    const btn = document.createElement("button");
    btn.id = "crc-review-btn";
    btn.textContent = "🤖 Review this PR";
    Object.assign(btn.style, {
      position: "fixed",
      bottom: "20px",
      right: "20px",
      zIndex: "9999",
      padding: "10px 14px",
      background: "#1f6feb",
      color: "#fff",
      border: "none",
      borderRadius: "6px",
      cursor: "pointer",
      fontWeight: "600",
      boxShadow: "0 2px 8px rgba(0,0,0,0.3)",
    });
    btn.addEventListener("click", runReview);
    document.body.appendChild(btn);
  }

  async function runReview() {
    const btn = document.getElementById("crc-review-btn");
    const base = prBaseUrl();
    if (!base) return;
    btn.textContent = "⏳ Reviewing…";
    btn.disabled = true;
    try {
      const diff = await (await fetch(base + ".diff")).text();
      const res = await chrome.runtime.sendMessage({
        type: "review",
        diff,
        pr_url: base,
      });
      if (res && res.ok) {
        const n = (res.report.report || res.report).issues.length;
        btn.textContent = `✅ ${n} finding(s) — open popup`;
      } else {
        btn.textContent = "⚠️ Error — open popup";
      }
    } catch (e) {
      btn.textContent = "⚠️ Failed — is the backend running?";
    } finally {
      btn.disabled = false;
      setTimeout(() => (btn.textContent = "🤖 Review this PR"), 6000);
    }
  }

  // GitHub navigates via pjax/turbo; re-add the button on DOM changes.
  addButton();
  new MutationObserver(addButton).observe(document.body, {
    childList: true,
    subtree: true,
  });
})();
