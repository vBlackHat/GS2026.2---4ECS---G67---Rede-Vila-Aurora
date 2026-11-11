FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN pip install --no-cache-dir --root-user-action=ignore paho-mqtt==2.1.0
WORKDIR /app
COPY agent.py .
CMD ["python", "agent.py"]
