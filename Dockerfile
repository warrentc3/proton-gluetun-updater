FROM python:3.15.0a8-alpine3.23

# Vuln safeguard: upgrade base packages at build time so a stale tag
# can't ship known-patched CVEs. Do not drop on aesthetic grounds —
# the trivy gate depends on this. Mirrors the prior apt-get upgrade -y.
RUN apk upgrade --no-cache && \
    apk add --no-cache git gnupg tzdata

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY countries.json index.html transform.py storage.py state.py protonvpn.py web.py protonvpn_gluetun_updater.py ./

# Default environment variables
ENV IP6=exclude

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen(f'http://localhost:{os.environ.get(\"WEB_PORT\",\"8080\")}/health')"

ENTRYPOINT ["python", "protonvpn_gluetun_updater.py"]
