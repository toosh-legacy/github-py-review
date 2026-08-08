// Renders the last scan/review result (from chrome.storage.local) and lets the
// user set the backend URL and an optional GitHub token.
//
// Two report shapes land here: a SecurityReport (`findings`, with detector
// provenance) from the repo scanner, and the code-review Report (`issues`) from
// the PR flow.

function escapeHtml(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}

const CATEGORY = {
  secret: { label: "Secret", icon: "🔑" },
  dependency: { label: "Dependency", icon: "📦" },
  code: { label: "Code", icon: "⚠️" },
};

const EXPLOITABILITY = {
  direct: "directly exploitable",
  conditional: "exploitable given a precondition",
  theoretical: "no plausible path here",
};

function fileLink(repo, ref, file, line) {
  if (!repo) return null;
  const anchor = line ? `#L${line}` : "";
  return `https://github.com/${repo}/blob/${encodeURIComponent(ref || "HEAD")}/${file}${anchor}`;
}

// ----- security report ------------------------------------------------------ //
function renderSecurity(record) {
  const report = record.report;
  const sev = report.counts_by_severity || {};
  const parts = [
    `<div class="summary"><b>${escapeHtml(record.repo || "repo")}</b>`,
    `${escapeHtml(ref(record))} · ${escapeHtml(report.summary)}`,
    `<br>${report.scanned_files} file(s) scanned · ${report.tokens_used} tokens · ${report.latency_ms} ms</div>`,
  ];

  if (sev.high || sev.medium || sev.low) {
    parts.push(
      `<div class="chips">` +
        chip("high", sev.high) +
        chip("medium", sev.medium) +
        chip("low", sev.low) +
        `</div>`
    );
  }

  if (record.truncated) {
    parts.push(
      `<div class="warn">Repository was larger than the scan cap — only the ` +
        `highest-priority files were sent.</div>`
    );
  }
  for (const note of report.degraded || []) {
    parts.push(`<div class="warn">${escapeHtml(note)}</div>`);
  }

  if (!report.findings.length) {
    parts.push(`<div class="issue low">No security findings. 🎉</div>`);
  }

  for (const f of report.findings) {
    const meta = CATEGORY[f.category] || { label: f.category, icon: "•" };
    const url = fileLink(record.repo, record.ref, f.file, f.line_start);
    const label = `${escapeHtml(f.file)}${f.line_start ? ":" + f.line_start : ""}`;
    const loc = url
      ? `<a class="loc" href="${url}" target="_blank">${label}</a>`
      : `<span class="loc">${label}</span>`;

    let html = `<div class="issue ${f.severity}">`;
    html += `<div class="head"><b>${f.severity}</b> · ${meta.icon} ${meta.label}`;
    html += ` · <span class="rule">${escapeHtml(f.rule_id)}</span></div>`;
    html += `<div class="title">${escapeHtml(f.title)}</div>`;
    html += `<div>${loc}</div>`;
    if (f.evidence) html += `<div class="evidence">${escapeHtml(f.evidence)}</div>`;
    if (f.explanation) html += `<div class="why">${escapeHtml(f.explanation)}</div>`;
    if (f.suggested_fix) html += `<div class="fix">${escapeHtml(f.suggested_fix)}</div>`;

    const tags = [`found by ${escapeHtml(f.detector)}`];
    if (f.exploitability) tags.push(EXPLOITABILITY[f.exploitability] || f.exploitability);
    if (f.merged_from && f.merged_from.length) {
      tags.push(`${f.merged_from.length} duplicate finding(s) merged`);
    }
    if (!f.triaged) tags.push("not triaged");
    html += `<div class="meta">${tags.join(" · ")}</div>`;

    for (const ref of (f.references || []).slice(0, 2)) {
      html += `<div class="meta"><a href="${escapeHtml(ref)}" target="_blank">${escapeHtml(ref)}</a></div>`;
    }
    html += `</div>`;
    parts.push(html);
  }
  return parts.join("");
}

function ref(record) {
  return record.ref ? `@${record.ref}` : "";
}

function chip(severity, count) {
  if (!count) return "";
  return `<span class="chip ${severity}">${count} ${severity}</span>`;
}

// ----- code-review report (PR flow) ----------------------------------------- //
function renderReview(record) {
  const report = record.report;
  const link = record.pr_url ? () => record.pr_url + "/files" : null;

  let html = `<div class="summary">Reviewed PR diff · ${escapeHtml(report.summary)} · ${report.tokens_used} tokens · ${report.latency_ms} ms</div>`;
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
  return html;
}

function render(record) {
  const el = document.getElementById("content");
  if (!record) return;
  if (record.error) {
    el.innerHTML = `<span style="color:#cf222e">${escapeHtml(record.error.message || "error")}</span>`;
    return;
  }
  el.innerHTML =
    record.kind === "security" ? renderSecurity(record) : renderReview(record);
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
