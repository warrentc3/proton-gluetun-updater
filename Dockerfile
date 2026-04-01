FROM --platform=$TARGETPLATFORM python:3.13.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends git gnupg && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY countries.json index.html transform.py storage.py state.py protonvpn.py web.py protonvpn_gluetun_updater.py ./

# Default environment variables
ENV IP6=exclude

ENTRYPOINT ["python", "protonvpn_gluetun_updater.py"]
