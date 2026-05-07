FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir .

EXPOSE 9000

CMD ["portmap-master", "--config", "docker/config/master.json"]
