FROM python:3.13-alpine

RUN apk add --no-cache tzdata \
 && addgroup -S exporter && adduser -S -G exporter -h /app exporter \
 && mkdir /data && chown exporter:exporter /data

WORKDIR /app
COPY --chown=exporter:exporter exporter.py /app/exporter.py

USER exporter
ENV PYTHONUNBUFFERED=1 \
    STATE_FILE=/data/state.json
VOLUME ["/data"]

HEALTHCHECK --interval=60s --timeout=5s --start-period=60s \
  CMD ["python", "/app/exporter.py", "--healthcheck"]

ENTRYPOINT ["python", "/app/exporter.py"]
