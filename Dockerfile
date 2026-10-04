FROM mcr.microsoft.com/playwright/python:v1.55.0-noble

WORKDIR /app
COPY requirements-api.txt requirements-rendered.txt ./
RUN pip install --no-cache-dir -r requirements-api.txt -r requirements-rendered.txt

COPY . .

ENV PYTHONUNBUFFERED=1
CMD ["sh", "-c", "uvicorn api:app --host 0.0.0.0 --port $PORT"]
