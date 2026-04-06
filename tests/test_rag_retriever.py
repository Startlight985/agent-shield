"""Tests for RAG retriever module."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import numpy as np
import pytest


def _build_test_kb(tmp_dir: Path, chunks: list[dict], dim: int = 384):
    """Helper: create rag_kb.npz + rag_kb.json with random embeddings."""
    n = len(chunks)
    # Use deterministic pseudo-embeddings based on text hash for reproducibility
    rng = np.random.RandomState(42)
    embeddings = rng.randn(n, dim).astype(np.float32)
    # Normalize
    norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
    embeddings = embeddings / np.maximum(norms, 1e-12)

    np.savez_compressed(str(tmp_dir / "rag_kb.npz"), embeddings=embeddings)
    meta = [{"category": c["category"], "title": c["title"],
             "text": c["text"], "index": i} for i, c in enumerate(chunks)]
    (tmp_dir / "rag_kb.json").write_text(json.dumps(meta), encoding="utf-8")
    return embeddings


class TestRAGRetrieverUnit:
    """Unit tests using synthetic KB (no real embedding model needed)."""

    def test_init_missing_kb(self, tmp_path):
        """Retriever gracefully handles missing KB files."""
        from agent_shield.a2a.rag_retriever import RAGRetriever
        r = RAGRetriever(data_dir=tmp_path)
        assert not r.available
        assert r.retrieve("anything") == []

    def test_init_empty_kb(self, tmp_path):
        """Retriever handles empty KB."""
        np.savez_compressed(str(tmp_path / "rag_kb.npz"),
                            embeddings=np.zeros((0, 384), dtype=np.float32))
        (tmp_path / "rag_kb.json").write_text("[]", encoding="utf-8")

        from agent_shield.a2a.rag_retriever import RAGRetriever
        r = RAGRetriever(data_dir=tmp_path)
        assert not r.available

    def test_load_valid_kb(self, tmp_path):
        """Retriever loads valid KB correctly."""
        from agent_shield.a2a.rag_retriever import RAGRetriever
        chunks = [
            {"category": "ethics", "title": "Test Ethics", "text": "Ethics content here."},
            {"category": "regulatory", "title": "Test HIPAA", "text": "HIPAA 164.512 content."},
        ]
        _build_test_kb(tmp_path, chunks)
        r = RAGRetriever(data_dir=tmp_path)
        assert r.available

    def test_category_filtering(self, tmp_path):
        """Category filter restricts search to matching chunks."""
        from agent_shield.a2a.rag_retriever import RAGRetriever
        chunks = [
            {"category": "ethics", "title": "Ethics A", "text": "Ethical AI content."},
            {"category": "regulatory", "title": "HIPAA Rule", "text": "HIPAA 45 CFR 164."},
            {"category": "ethics", "title": "Ethics B", "text": "More ethics content."},
        ]
        _build_test_kb(tmp_path, chunks)
        r = RAGRetriever(data_dir=tmp_path)

        # Category index should be built
        assert "ethics" in r._cat_indices
        assert "regulatory" in r._cat_indices
        assert len(r._cat_indices["ethics"]) == 2
        assert len(r._cat_indices["regulatory"]) == 1

    def test_format_context_empty(self):
        """format_context returns empty string for no results."""
        from agent_shield.a2a.rag_retriever import RAGRetriever
        r = RAGRetriever.__new__(RAGRetriever)
        assert r.format_context([]) == ""

    def test_format_context_truncation(self):
        """format_context respects max_chars limit."""
        from agent_shield.a2a.rag_retriever import RAGRetriever
        r = RAGRetriever.__new__(RAGRetriever)
        results = [
            {"title": "T1", "text": "A" * 500, "score": 0.9},
            {"title": "T2", "text": "B" * 500, "score": 0.8},
            {"title": "T3", "text": "C" * 500, "score": 0.7},
        ]
        ctx = r.format_context(results, max_chars=200)
        assert len(ctx) <= 200
        assert ctx.startswith("[Reference]")

    def test_format_context_content(self):
        """format_context includes title and text."""
        from agent_shield.a2a.rag_retriever import RAGRetriever
        r = RAGRetriever.__new__(RAGRetriever)
        results = [
            {"title": "HIPAA Rule", "text": "45 CFR 164.512", "score": 0.9},
        ]
        ctx = r.format_context(results)
        assert "[Reference]" in ctx
        assert "HIPAA Rule" in ctx
        assert "164.512" in ctx


class TestRAGRetrieverIntegration:
    """Integration tests requiring the real embedding model."""

    @pytest.fixture(autouse=True)
    def _check_model(self):
        """Skip if no embedding model available."""
        try:
            from agent_shield.a2a.embedding_riverbed import _get_model
            model = _get_model()
            if model is None:
                pytest.skip("No embedding model available")
        except Exception:
            pytest.skip("Embedding model import failed")

    def _build_real_kb(self, tmp_path: Path):
        """Build a real KB with actual embeddings."""
        from agent_shield.a2a.embedding_riverbed import _get_model
        model = _get_model()

        chunks = [
            {"category": "ethics", "title": "AI Hiring Ethics",
             "text": "Using AI for hiring decisions raises concerns about algorithmic bias and fairness."},
            {"category": "regulatory", "title": "HIPAA Privacy Rule",
             "text": "HIPAA 45 CFR Part 164 governs disclosure of Protected Health Information. Patient records cannot be shared with law enforcement without court order."},
            {"category": "medical", "title": "DIPG Overview",
             "text": "Diffuse Intrinsic Pontine Glioma is an aggressive pediatric brain tumor with poor prognosis."},
            {"category": "cultural", "title": "Cultural Relativism",
             "text": "Cultural relativism holds that moral standards are culturally defined. Avoid Western-centric assumptions."},
            {"category": "safe_categories", "title": "Security Research",
             "text": "Security research about vulnerabilities is legitimate when aimed at improving defenses."},
        ]

        texts = [f"{c['title']}: {c['text']}" for c in chunks]
        embeddings = model.encode(texts, normalize_embeddings=True).astype(np.float32)
        np.savez_compressed(str(tmp_path / "rag_kb.npz"), embeddings=embeddings)
        meta = [{"category": c["category"], "title": c["title"],
                 "text": c["text"], "index": i} for i, c in enumerate(chunks)]
        (tmp_path / "rag_kb.json").write_text(json.dumps(meta), encoding="utf-8")

    def test_ethics_retrieval(self, tmp_path):
        from agent_shield.a2a.rag_retriever import RAGRetriever
        self._build_real_kb(tmp_path)
        r = RAGRetriever(data_dir=tmp_path)
        results = r.retrieve("Is it ethical to use AI for hiring?", category="ethics")
        assert len(results) > 0
        assert results[0]["score"] > 0.3

    def test_regulatory_retrieval(self, tmp_path):
        from agent_shield.a2a.rag_retriever import RAGRetriever
        self._build_real_kb(tmp_path)
        r = RAGRetriever(data_dir=tmp_path)
        results = r.retrieve("Can I share patient records with law enforcement?",
                             category="regulatory")
        assert len(results) > 0
        assert "HIPAA" in results[0]["text"] or "164" in results[0]["text"]

    def test_cross_category_retrieval(self, tmp_path):
        """Without category filter, retrieval searches all chunks."""
        from agent_shield.a2a.rag_retriever import RAGRetriever
        self._build_real_kb(tmp_path)
        r = RAGRetriever(data_dir=tmp_path)
        results = r.retrieve("What is DIPG and how is it treated?", top_k=3, threshold=0.3)
        assert len(results) > 0
        # Medical chunk should rank high
        titles = [r["title"] for r in results]
        assert "DIPG Overview" in titles

    def test_retrieve_threshold_filtering(self, tmp_path):
        """Very high threshold should return fewer/no results."""
        from agent_shield.a2a.rag_retriever import RAGRetriever
        self._build_real_kb(tmp_path)
        r = RAGRetriever(data_dir=tmp_path)
        results = r.retrieve("completely unrelated query about cooking recipes",
                             threshold=0.95)
        # Should return 0 or at most 1 (relaxed threshold fallback)
        assert len(results) <= 1
