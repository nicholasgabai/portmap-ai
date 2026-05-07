FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir .

EXPOSE 9100

CMD ["portmap-orchestrator", "--config", "docker/config/orchestrator.json"]
