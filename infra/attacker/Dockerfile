FROM python:3.12-slim
RUN pip install --no-cache-dir --root-user-action=ignore sqlmap==1.8.11
COPY cliente.py /usr/local/bin/cliente.py
WORKDIR /trabalho
CMD ["sleep", "infinity"]
