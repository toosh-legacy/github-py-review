// Renders the last scan and holds the two settings.
//
// Everything shown here came from a scan that ran locally; no report was ever
// sent anywhere. The "code analysis needs the CLI" note is deliberately part of
// the result rather than buried in help, because a partial scan presented as a
// clean one is the failure mode that matters for a security tool.

function escapeHtml(s) {
  return String(s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]
  );
}

const CATEGORY = {
  secret: { label: "Secret", icon: "🔑" },
  dependency: { label: "Dependency", icon: "📦" },
};

function fileLink(repo, ref, file, line) {
  if (!repo || !file) return null;
  const anchor = line ? `#L${line}` : "";
  return `https://github.com/${repo}/blob/${encodeURIComponent(ref || "HEAD")}/${file}${anchor}`;
}

function chip(severity, count) {
  return count ? `<span class="chip ${severity}">${count} ${severity}</span>` : "";
}

function renderFinding(f, report) {
  const meta = CATEGORY[f.category] || { label: f.category, icon: "•" };
  const url = fileLink(report.repo, report.ref, f.file, f.line_start);
  const label = `${escapeHtml(f.file)}${f.line_start ? ":" + f.line_start : ""}`;
  const loc = url
    ? `<a class="loc" href="${url}" target="_blank" rel="noreferrer">${label}</a>`
    : `<span class="loc">${label}</span>`;

  let html = `<div class="issue ${f.severity}">`;
  html += `<div class="head"><b>${f.severity}</b> · ${meta.icon} ${meta.label} · `;
  html += `<span class="rule">${escapeHtml(f.rule_id)}</span></div>`;
  html += `<div class="title">${escapeHtml(f.title)}</div>`;
  html += `<div>${loc}</div>`;
  if (f.evidence) html += `<div class="evidence">${escapeHtml(f.evidence)}</div>`;
  if (f.explanation) html += `<div class="why">${escapeHtml(f.explanation)}</div>`;
  if (f.suggested_fix) html += `<div class="fix">${escapeHtml(f.suggested_fix)}</div>`;
  for (const ref of (f.references || []).slice(0, 2)) {
    html += `<div class="meta"><a href="${escapeHtml(ref)}" target="_blank" rel="noreferrer">${escapeHtml(ref)}</a></div>`;
  }
  html += `</div>`;
  return html;
}

function render(report) {
  const el = document.getElementById("content");
  if (!report) return;

  if (report.error) {
    el.innerHTML = `<div class="warn err">${escapeHtml(report.error.message || "error")}</div>`;
    return;
  }

  const sev = report.counts_by_severity || {};
  const parts = [
    `<div class="summary"><b>${escapeHtml(report.repo || "repo")}</b>`,
    report.ref ? `<span class="dim">@${escapeHtml(report.ref)}</span>` : "",
    `<br>${escapeHtml(report.summary)}`,
    `<br><span class="dim">${report.scanned_files} file(s) scanned`,
    report.suppressed ? ` · ${report.suppressed} suppressed` : "",
    `</span></div>`,
  ];

  if (sev.high || sev.medium || sev.low) {
    parts.push(
      `<div class="chips">${chip("high", sev.high)}${chip("medium", sev.medium)}${chip("low", sev.low)}</div>`
    );
  }

  for (const note of report.degraded || []) {
    parts.push(`<div class="warn">${escapeHtml(note)}</div>`);
  }

  if (!report.findings.length) {
    parts.push(`<div class="issue low">No secrets or vulnerable dependencies found. 🎉</div>`);
  }
  for (const f of report.findings) parts.push(renderFinding(f, report));

  el.innerHTML = parts.join("");
}

chrome.storage.local.get(["lastScan", "ghToken"]).then((data) => {
  render(data.lastScan);
  if (data.ghToken) document.getElementById("ghToken").value = data.ghToken;
});

document.getElementById("save").addEventListener("click", async () => {
  const btn = document.getElementById("save");
  await chrome.storage.local.set({
    ghToken: document.getElementById("ghToken").value.trim(),
  });
  btn.textContent = "Saved";
  setTimeout(() => (btn.textContent = "Save"), 1500);
});
