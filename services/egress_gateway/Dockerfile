FROM python:3.11-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY pyproject.toml /app/pyproject.toml
RUN pip install --no-cache-dir -U pip \
  && pip install --no-cache-dir .

COPY app /app/app

EXPOSE 8080
CMD ["uvicorn", "app.main:APP", "--host", "0.0.0.0", "--port", "8080"]
