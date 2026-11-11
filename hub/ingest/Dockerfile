FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN pip install --no-cache-dir --root-user-action=ignore "psycopg[binary]==3.2.3"
WORKDIR /app
COPY app.py .
CMD ["python", "app.py"]
