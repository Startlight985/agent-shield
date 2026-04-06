#!/usr/bin/env python3
"""Build RAG knowledge base: embed all .jsonl chunks into rag_kb.npz + rag_kb.json.

Run during Docker build (after ONNX models are available) or locally for dev.

Usage:
    python scripts/build_rag_kb.py --onnx-dir src/agent_shield/a2a/onnx_models/embed
    python scripts/build_rag_kb.py  # auto-detect or fall back to sentence-transformers
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import numpy as np

log = logging.getLogger("build_rag_kb")

_KNOWLEDGE_DIR = Path(__file__).resolve().parent.parent / "data" / "knowledge"
_OUTPUT_DIR = Path(__file__).resolve().parent.parent / "data"


def _load_chunks(knowledge_dir: Path) -> list[dict]:
    """Read all .jsonl files from knowledge directory."""
    chunks = []
    idx = 0
    for jf in sorted(knowledge_dir.glob("*.jsonl")):
        for line_no, line in enumerate(jf.read_text(encoding="utf-8").splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                log.warning("Skipping invalid JSON in %s:%d", jf.name, line_no)
                continue
            obj["index"] = idx
            # Ensure required fields
            for field in ("category", "title", "text"):
                if field not in obj:
                    log.warning("Missing field '%s' in %s:%d, skipping", field, jf.name, line_no)
                    break
            else:
                chunks.append(obj)
                idx += 1
    return chunks


def _get_embedder(onnx_dir: str | None):
    """Load embedding model: ONNX first, fallback to sentence-transformers."""
    if onnx_dir:
        onnx_path = Path(onnx_dir)
        if (onnx_path / "model.onnx").exists():
            try:
                import onnxruntime as ort  # noqa: F401
                from transformers import AutoTokenizer

                # Inline minimal embedder (same logic as _OnnxEmbedder)
                tokenizer = AutoTokenizer.from_pretrained(str(onnx_path))
                session = ort.InferenceSession(
                    str(onnx_path / "model.onnx"),
                    providers=["CPUExecutionProvider"],
                )
                input_names = {inp.name for inp in session.get_inputs()}

                def embed(texts: list[str]) -> np.ndarray:
                    encoded = tokenizer(
                        texts, padding=True, truncation=True,
                        max_length=256, return_tensors="np",
                    )
                    feed = {
                        "input_ids": encoded["input_ids"].astype(np.int64),
                        "attention_mask": encoded["attention_mask"].astype(np.int64),
                    }
                    if "token_type_ids" in input_names:
                        feed["token_type_ids"] = encoded.get(
                            "token_type_ids", np.zeros_like(feed["input_ids"]),
                        ).astype(np.int64)
                    outputs = session.run(None, feed)
                    token_emb = outputs[0]
                    mask = encoded["attention_mask"][..., np.newaxis].astype(np.float32)
                    pooled = (token_emb * mask).sum(axis=1) / np.maximum(mask.sum(axis=1), 1e-12)
                    norms = np.linalg.norm(pooled, axis=1, keepdims=True)
                    return (pooled / np.maximum(norms, 1e-12)).astype(np.float32)

                log.info("Using ONNX embedder from %s", onnx_path)
                return embed
            except Exception as e:
                log.warning("ONNX load failed: %s, trying sentence-transformers", e)

    # Fallback: sentence-transformers
    try:
        from sentence_transformers import SentenceTransformer
        model = SentenceTransformer("paraphrase-multilingual-MiniLM-L12-v2")
        log.info("Using sentence-transformers embedder")

        def embed(texts: list[str]) -> np.ndarray:
            return model.encode(texts, normalize_embeddings=True).astype(np.float32)

        return embed
    except ImportError:
        log.error("No embedding backend available (need onnxruntime or sentence-transformers)")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Build RAG knowledge base embeddings")
    parser.add_argument("--onnx-dir", default=None, help="Path to ONNX embed model dir")
    parser.add_argument("--knowledge-dir", default=str(_KNOWLEDGE_DIR), help="Knowledge .jsonl dir")
    parser.add_argument("--output-dir", default=str(_OUTPUT_DIR), help="Output directory")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    knowledge_dir = Path(args.knowledge_dir)
    output_dir = Path(args.output_dir)

    if not knowledge_dir.exists():
        log.error("Knowledge directory not found: %s", knowledge_dir)
        sys.exit(1)

    chunks = _load_chunks(knowledge_dir)
    if not chunks:
        log.warning("No chunks found in %s — creating empty KB", knowledge_dir)
        np.savez_compressed(str(output_dir / "rag_kb.npz"), embeddings=np.zeros((0, 384), dtype=np.float32))
        (output_dir / "rag_kb.json").write_text("[]", encoding="utf-8")
        return

    log.info("Loaded %d chunks from %s", len(chunks), knowledge_dir)

    embed_fn = _get_embedder(args.onnx_dir)

    # Embed all chunks (batch for efficiency)
    texts = [f"{c['title']}: {c['text']}" for c in chunks]
    BATCH_SIZE = 32
    all_embeddings = []
    for i in range(0, len(texts), BATCH_SIZE):
        batch = texts[i : i + BATCH_SIZE]
        emb = embed_fn(batch)
        all_embeddings.append(emb)
        log.info("  Embedded %d/%d", min(i + BATCH_SIZE, len(texts)), len(texts))

    embeddings = np.vstack(all_embeddings)  # (N, 384)
    log.info("Embeddings shape: %s", embeddings.shape)

    # Save outputs
    output_dir.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(str(output_dir / "rag_kb.npz"), embeddings=embeddings)

    metadata = [
        {"category": c["category"], "title": c["title"], "text": c["text"], "index": c["index"]}
        for c in chunks
    ]
    (output_dir / "rag_kb.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8",
    )

    log.info("Saved rag_kb.npz (%d, %d) and rag_kb.json (%d chunks) to %s",
             embeddings.shape[0], embeddings.shape[1], len(metadata), output_dir)


if __name__ == "__main__":
    main()
