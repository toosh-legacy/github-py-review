// Renders the last review/debug result (from chrome.storage.local) and lets the
// user set the backend URL and an optional GitHub token (for repo scanning).

function escapeHtml(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}

// Where an issue location should link, given the record's source context.
function locLinker(record) {
  if (record.kind === "debug" && record.repo) {
    const file = record.file;
    return (issue) =>
      `https://github.com/${record.repo}/blob/HEAD/${file}#L${issue.line_start}`;
  }
  if (record.pr_url) {
    const filesUrl = record.pr_url + "/files";
    return () => filesUrl;
  }
  return null;
}

function render(record) {
  const el = document.getElementById("content");
  if (!record) return;
  if (record.error) {
    el.innerHTML = `<span style="color:#cf222e">${escapeHtml(record.error.message || "error")}</span>`;
    return;
  }
  const report = record.report;
  const link = locLinker(record);
  const scope =
    record.kind === "debug"
      ? `Debugged <code>${escapeHtml(record.file || "")}</code>`
      : "Reviewed PR diff";

  let html = `<div class="summary">${scope} · ${escapeHtml(report.summary)} · ${report.tokens_used} tokens · ${report.latency_ms} ms</div>`;
  if (!report.issues.length) {
    html += `<div class="issue low">No issues found. 🎉</div>`;
  }
  for (const i of report.issues) {
    const label = `${escapeHtml(i.file)}:${i.line_start}`;
    const loc = link
      ? `<a class="loc" href="${link(i)}" target="_blank">${label}</a>`
      : `<span class="loc">${label}</span>`;
    html += `<div class="issue ${i.severity}"><b>${i.severity}</b> ${loc}<br>${escapeHtml(i.description)}`;
    if (i.suggested_fix) html += `<div class="fix">${escapeHtml(i.suggested_fix)}</div>`;
    html += `</div>`;
  }
  el.innerHTML = html;
}

chrome.storage.local.get(["lastReview", "backendUrl", "ghToken"]).then((data) => {
  render(data.lastReview);
  if (data.backendUrl) document.getElementById("backend").value = data.backendUrl;
  if (data.ghToken) document.getElementById("ghToken").value = data.ghToken;
});

document.getElementById("save").addEventListener("click", () => {
  const url = document.getElementById("backend").value.trim();
  const ghToken = document.getElementById("ghToken").value.trim();
  chrome.storage.local.set({
    backendUrl: url || "http://localhost:8001",
    ghToken,
  });
  const btn = document.getElementById("save");
  btn.textContent = "Saved";
  setTimeout(() => (btn.textContent = "Save"), 1500);
});
