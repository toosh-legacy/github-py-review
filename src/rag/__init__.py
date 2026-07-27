"""Chroma-backed retrieval over the files a diff touches. Optional at runtime:
everything in `indexer.py` degrades to a no-op when `chromadb` isn't installed."""
