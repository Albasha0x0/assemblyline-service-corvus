FROM cccs/assemblyline-v4-service-base:4.7.4.stable24@sha256:fb55e0b9179d7e5ea76d40802a4c2223f0cfa7892aa123b52dda359bdb38e82e

ENV SERVICE_PATH=corvus_service.corvus.Corvus
# Corvus never downloads in the service; what it could not read offline is reported as unknown.
ENV CORVUS_PATH=/opt/corvus/corvus \
    CORVUS_OFFLINE=1 \
    CORVUS_DATA_DIR=/tmp/corvus-data

# The Corvus release and its linux-x64 archive's SHA-256; both change together.
ARG CORVUS_VERSION=2.8.0
ARG CORVUS_SHA256=a0ae45539fe0b401567b0da53eb97a00bc7be96fc922e1b2c6db57e4a1fde940
USER root
COPY scripts/install_corvus.py /tmp/install_corvus.py
RUN python3 -I /tmp/install_corvus.py --version "$CORVUS_VERSION" --sha256 "$CORVUS_SHA256" --dest /opt/corvus && \
    rm /tmp/install_corvus.py

USER assemblyline
RUN /opt/corvus/corvus version
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir --user --requirement requirements.txt && \
    rm -rf ~/.cache/pip

WORKDIR /opt/al_service
COPY . .

ARG version=1.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

USER assemblyline
