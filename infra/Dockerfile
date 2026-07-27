FROM python:3.13-slim

WORKDIR /app

# Build context is the repo root (see docker-compose.yml / fly.toml).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# All Python packages live under src/, which is the import root.
COPY src ./src
ENV PYTHONPATH=/app/src

EXPOSE 8001
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8001"]
