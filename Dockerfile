# ── Stage 1: Export models to ONNX (thrown away after build) ──
FROM python:3.11-slim AS exporter

WORKDIR /export
RUN pip install --no-cache-dir \
    optimum[onnxruntime]>=1.17 \
    sentence-transformers>=3.0 \
    transformers>=4.38 \
    torch --extra-index-url https://download.pytorch.org/whl/cpu

COPY scripts/export_onnx.py scripts/export_onnx.py
COPY src/ src/

RUN python scripts/export_onnx.py --output-dir /export/onnx_models --skip-verify

# ── Stage 2: Slim runtime (no torch) ──
FROM python:3.11-slim

WORKDIR /app
COPY . .

# Install runtime deps only (onnxruntime, no torch)
RUN pip install --no-cache-dir -e ".[a2a,onnx]"

# Copy pre-exported ONNX models from stage 1
COPY --from=exporter /export/onnx_models/ src/agent_shield/a2a/onnx_models/

# Pre-compute RAG knowledge base embeddings (ONNX models now available)
RUN python scripts/build_rag_kb.py --onnx-dir src/agent_shield/a2a/onnx_models/embed

ENV A2A_PORT=8420
ENV A2A_LLM_PROVIDER=cascade
ENV A2A_LLM_MODEL=

EXPOSE 8420

HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8420/.well-known/agent-card.json')" || exit 1

ENTRYPOINT ["agent-shield-server"]
CMD ["--host", "0.0.0.0", "--port", "8420"]
