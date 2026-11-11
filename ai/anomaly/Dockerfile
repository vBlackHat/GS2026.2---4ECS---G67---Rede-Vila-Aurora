FROM python:3.12-slim
RUN pip install --no-cache-dir --root-user-action=ignore \
      scikit-learn==1.5.2 pandas==2.2.3 numpy==2.1.3
COPY detector.py /app/detector.py
WORKDIR /app
CMD ["python", "detector.py"]
