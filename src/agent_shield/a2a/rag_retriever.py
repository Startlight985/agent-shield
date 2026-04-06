"""RAG Retriever — cosine similarity search over pre-embedded knowledge base.

Reuses the embedding model from embedding_riverbed._get_model() to avoid
loading a second model instance.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import numpy as np

log = logging.getLogger("a2a.rag_retriever")

_DATA_DIR = Path(__file__).resolve().parent.parent.parent.parent / "data"

# Singleton
_retriever: RAGRetriever | None = None


class RAGRetriever:
    """Cosine-similarity retriever over pre-embedded knowledge chunks."""

    def __init__(self, data_dir: Path | str | None = None):
        data_dir = Path(data_dir) if data_dir else _DATA_DIR
        npz_path = data_dir / "rag_kb.npz"
        json_path = data_dir / "rag_kb.json"

        if not npz_path.exists() or not json_path.exists():
            log.warning("RAG KB not found at %s — retriever disabled", data_dir)
            self._embeddings = np.zeros((0, 384), dtype=np.float32)
            self._chunks: list[dict[str, Any]] = []
            self._available = False
            return

        loaded = np.load(str(npz_path))
        self._embeddings = loaded["embeddings"].astype(np.float32)  # (N, dim)
        self._chunks = json.loads(json_path.read_text(encoding="utf-8"))
        self._available = len(self._chunks) > 0

        # Pre-normalize embeddings for fast cosine similarity
        norms = np.linalg.norm(self._embeddings, axis=1, keepdims=True)
        self._embeddings_normed = self._embeddings / np.maximum(norms, 1e-12)

        # Build category index for fast filtering
        self._cat_indices: dict[str, list[int]] = {}
        for i, chunk in enumerate(self._chunks):
            cat = chunk.get("category", "")
            self._cat_indices.setdefault(cat, []).append(i)

        log.info("RAG KB loaded: %d chunks, %d categories",
                 len(self._chunks), len(self._cat_indices))

    @property
    def available(self) -> bool:
        return self._available

    def retrieve(
        self,
        query: str,
        category: str | None = None,
        top_k: int = 3,
        threshold: float = 0.5,
    ) -> list[dict[str, Any]]:
        """Retrieve top-k chunks above threshold for the given query.

        Args:
            query: The search query text.
            category: Optional category filter (e.g., "ethics", "regulatory").
            top_k: Maximum number of results to return.
            threshold: Minimum cosine similarity score.

        Returns:
            List of {"title", "text", "score"} dicts, sorted by score descending.
        """
        if not self._available:
            return []

        # Embed query using the shared model from embedding_riverbed
        query_vec = self._embed_query(query)
        if query_vec is None:
            return []

        # Normalize query
        qnorm = np.linalg.norm(query_vec)
        if qnorm < 1e-12:
            return []
        query_normed = query_vec / qnorm

        # Determine candidate indices
        if category and category in self._cat_indices:
            indices = np.array(self._cat_indices[category])
            candidates = self._embeddings_normed[indices]
        else:
            indices = np.arange(len(self._chunks))
            candidates = self._embeddings_normed

        # Cosine similarity (dot product of normalized vectors)
        scores = candidates @ query_normed  # (M,)

        # Filter by threshold and get top-k
        above_mask = scores >= threshold
        if not above_mask.any():
            # Relax threshold: return best match if score > 0.3
            best_idx = int(np.argmax(scores))
            if scores[best_idx] > 0.3:
                real_idx = int(indices[best_idx])
                chunk = self._chunks[real_idx]
                return [{"title": chunk["title"], "text": chunk["text"],
                         "score": float(scores[best_idx])}]
            return []

        valid_scores = scores[above_mask]
        valid_indices = indices[above_mask]

        # Sort descending, take top_k
        top_order = np.argsort(-valid_scores)[:top_k]

        results = []
        for o in top_order:
            real_idx = int(valid_indices[o])
            chunk = self._chunks[real_idx]
            results.append({
                "title": chunk["title"],
                "text": chunk["text"],
                "score": float(valid_scores[o]),
            })
        return results

    def format_context(self, results: list[dict[str, Any]], max_chars: int = 2000) -> str:
        """Format retrieval results as context for LLM injection.

        Args:
            results: Output from retrieve().
            max_chars: Maximum characters (~500 tokens).

        Returns:
            Formatted reference string, or empty string if no results.
        """
        if not results:
            return ""

        lines = ["[Reference]"]
        total = len(lines[0])
        for r in results:
            entry = f"- {r['title']}: {r['text']}"
            if total + len(entry) + 1 > max_chars:
                # Truncate this entry to fit
                remaining = max_chars - total - 1
                if remaining > 50:
                    entry = entry[:remaining - 3] + "..."
                else:
                    break
            lines.append(entry)
            total += len(entry) + 1  # +1 for newline
        return "\n".join(lines)

    @staticmethod
    def _embed_query(text: str) -> np.ndarray | None:
        """Embed a query using the shared model from embedding_riverbed."""
        try:
            from agent_shield.a2a.embedding_riverbed import _get_model
            model = _get_model()
            if model is None:
                return None
            vec = model.encode(text, normalize_embeddings=True)
            return vec.astype(np.float32)
        except Exception as e:
            log.warning("RAG query embedding failed: %s", e)
            return None


def get_rag_retriever() -> RAGRetriever:
    """Get or create the singleton RAGRetriever instance."""
    global _retriever
    if _retriever is None:
        _retriever = RAGRetriever()
    return _retriever
