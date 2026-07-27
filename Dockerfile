FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# One COPY per top-level package, so it's obvious what ships in the image.
COPY config.py schemas.py ./
COPY backend ./backend
COPY agent ./agent
COPY llm_model ./llm_model
COPY database ./database
COPY github_client ./github_client
COPY mcp_server ./mcp_server
COPY rag ./rag

EXPOSE 8001
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8001"]
