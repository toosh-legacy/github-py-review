"""RAG over the files a diff touches, using a local Chroma store.

Scope is deliberately small (spec): index only the changed files (plus, when
available, their direct imports) — not the whole repo — so indexing stays fast.

Everything degrades to a no-op when `chromadb` isn't installed, so the rest of
the app runs unchanged without it. `index_diff_files` is safe to call on every
review; `search` returns "" when nothing is indexed.
"""
from __future__ import annotations

import re

from agent.diff_utils import DiffFile

_COLLECTION = "repo_context"
_IMPORT_RE = re.compile(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))", re.M)

_client = None


def _get_collection():
    """Return the Chroma collection, or None if chromadb is unavailable."""
    global _client
    try:
        import chromadb  # lazy, optional
    except Exception:  # noqa: BLE001
        return None
    if _client is None:
        _client = chromadb.PersistentClient(path=".chroma")
    return _client.get_or_create_collection(_COLLECTION)


def rag_available() -> bool:
    """True when the Chroma store is usable (chromadb installed)."""
    return _get_collection() is not None


def _direct_imports(content: str) -> list[str]:
    mods = []
    for m in _IMPORT_RE.finditer(content):
        mods.append((m.group(1) or m.group(2)).split(".")[0])
    return sorted(set(mods))


def index_files(files: list[tuple[str, str]]) -> int:
    """Index whole files given as (path, content) pairs. Returns count indexed.

    Unlike `index_diff_files` (which indexes the partial content reconstructed
    from a diff), this stores full file contents — used by POST /scan/repo to
    build repo context for the debug flow. No-op without chromadb.
    """
    coll = _get_collection()
    if coll is None or not files:
        return 0
    ids, docs, metas = [], [], []
    for path, content in files:
        if not content.strip():
            continue
        ids.append(path)
        docs.append(content)
        metas.append({"path": path, "imports": ",".join(_direct_imports(content))})
    if not ids:
        return 0
    coll.upsert(ids=ids, documents=docs, metadatas=metas)
    return len(ids)


def index_diff_files(files: list[DiffFile]) -> int:
    """Index the reconstructed content of touched Python files. Returns count."""
    coll = _get_collection()
    if coll is None or not files:
        return 0
    ids, docs, metas = [], [], []
    for df in files:
        content, _ = df.reconstructed_new_content()
        if not content.strip():
            continue
        ids.append(df.path)
        docs.append(content)
        metas.append({"path": df.path, "imports": ",".join(_direct_imports(content))})
    if not ids:
        return 0
    coll.upsert(ids=ids, documents=docs, metadatas=metas)
    return len(ids)


def search(query: str, k: int = 4) -> str:
    """Return the top-k indexed snippets relevant to `query` (or "")."""
    coll = _get_collection()
    if coll is None:
        return ""
    try:
        res = coll.query(query_texts=[query], n_results=k)
    except Exception:  # noqa: BLE001 - empty collection, etc.
        return ""
    docs = (res.get("documents") or [[]])[0]
    return "\n\n---\n\n".join(docs)
