FROM cccs/assemblyline-v4-service-base:4.7.4.stable24@sha256:fb55e0b9179d7e5ea76d40802a4c2223f0cfa7892aa123b52dda359bdb38e82e

ENV SERVICE_PATH=corvus_service.corvus.Corvus
# Corvus never downloads in the service; what it could not read offline is reported as unknown.
ENV CORVUS_PATH=/opt/corvus/corvus \
    CORVUS_OFFLINE=1 \
    CORVUS_DATA_DIR=/tmp/corvus-data

# The Corvus release and its linux-x64 archive's SHA-256; both change together.
ARG CORVUS_VERSION=2.7.2
ARG CORVUS_SHA256=295fcb56102683fd0ba94b022eae14424f976fadab7c65057d37d3a18ee9be08
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
