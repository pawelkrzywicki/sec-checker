FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home reviewer && mkdir /state && chown reviewer:reviewer /state
COPY findings.py app.py jobs.py scanner.py gunicorn.conf.py affected-certificates.json ./
COPY templates/ ./templates/
COPY static/ ./static/
USER 10001:10001
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/health', timeout=2)"
CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]
