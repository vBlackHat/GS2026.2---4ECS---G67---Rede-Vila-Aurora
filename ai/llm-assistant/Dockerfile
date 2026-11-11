# Assistente de IA com guardrails (B27). Sem dependencias externas:
# usa apenas a stdlib (urllib) para falar com o Ollama na rede isolada vila_ai.
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY guardrails.py assistente.py testes.py ./
CMD ["python", "testes.py"]
