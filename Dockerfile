FROM mcr.microsoft.com/playwright/python:v1.55.0-noble

WORKDIR /app
COPY requirements-api.txt requirements-rendered.txt ./
RUN pip install --no-cache-dir -r requirements-api.txt -r requirements-rendered.txt

COPY . .

# Fail the image build if the production entrypoint is syntactically invalid.
RUN python -m py_compile api.py

ENV PYTHONUNBUFFERED=1
EXPOSE 10000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:' + __import__('os').environ.get('PORT','10000') + '/health', timeout=3)"

CMD ["sh", "-c", "uvicorn api:app --host 0.0.0.0 --port $PORT"]
