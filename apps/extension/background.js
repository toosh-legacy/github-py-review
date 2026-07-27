// Service worker: receives a review (PR diff) or debug (single file) request
// from a content script, posts it to the backend, and stashes the result for
// the popup to render.

const DEFAULT_BACKEND = "http://localhost:8001";

async function backendUrl() {
  const { backendUrl } = await chrome.storage.local.get("backendUrl");
  return (backendUrl || DEFAULT_BACKEND).replace(/\/$/, "");
}

// Map each request type to its endpoint + JSON body, and to the context we
// stash alongside the report so the popup can link back to the source.
function requestFor(msg) {
  if (msg.type === "review") {
    return {
      path: "/review/full",
      body: { diff: msg.diff },
      context: { kind: "review", pr_url: msg.pr_url },
    };
  }
  if (msg.type === "debug") {
    return {
      path: "/debug/file/full",
      body: { path: msg.path, content: msg.content, repo: msg.repo },
      context: { kind: "debug", repo: msg.repo, file: msg.path },
    };
  }
  return null;
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  const req = requestFor(msg);
  if (!req) return;
  (async () => {
    try {
      const base = await backendUrl();
      const resp = await fetch(base + req.path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(req.body),
      });
      const data = await resp.json();
      if (!resp.ok) {
        await chrome.storage.local.set({ lastReview: { error: data.error } });
        sendResponse({ ok: false, error: data.error });
        return;
      }
      const record = { ...data, ...req.context };
      await chrome.storage.local.set({ lastReview: record });
      chrome.action.setBadgeText({ text: String(record.report.issues.length) });
      chrome.action.setBadgeBackgroundColor({ color: "#8250df" });
      sendResponse({ ok: true, report: record });
    } catch (e) {
      sendResponse({ ok: false, error: { message: String(e) } });
    }
  })();
  return true; // keep the message channel open for the async response
});
