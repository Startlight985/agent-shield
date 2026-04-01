FROM python:3.11-slim

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -e ".[a2a]"

ENV A2A_PORT=8420
ENV A2A_LLM_PROVIDER=anthropic
ENV A2A_LLM_MODEL=claude-haiku-4-5-20251001

EXPOSE 8420

HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8420/.well-known/agent-card.json')" || exit 1

CMD ["agent-shield-server"]
