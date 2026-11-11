FROM python:3.12-slim
RUN pip install --no-cache-dir --root-user-action=ignore \
      dkimpy==1.1.8 pyspf==2.0.14 dnspython==2.6.1 cryptography==43.0.1
COPY gerar_dkim.py mailer.py validador.py campanha.py /app/
WORKDIR /app
CMD ["sleep", "infinity"]
