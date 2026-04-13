FROM python:3.14.0-slim

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends git gnupg && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY countries.json index.html transform.py storage.py state.py protonvpn.py web.py protonvpn_gluetun_updater.py ./

# Default environment variables
ENV IP6=exclude

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen(f'http://localhost:{os.environ.get(\"WEB_PORT\",\"8080\")}/health')"

ENTRYPOINT ["python", "protonvpn_gluetun_updater.py"]
