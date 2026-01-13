FROM python:3.11-slim

WORKDIR /workspace

RUN pip install --no-cache-dir httpx==0.27.0

CMD ["python", "scripts/e2e_runner.py"]
