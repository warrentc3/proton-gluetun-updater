FROM --platform=$TARGETPLATFORM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends git gnupg && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY protonvpn_gluetun_updater.py countries.json ./

# Default environment variables
ENV IP6=exclude

HEALTHCHECK --interval=60s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

ENTRYPOINT ["python", "protonvpn_gluetun_updater.py"]
