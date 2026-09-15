FROM jrei/systemd-ubuntu:24.04

# Install.sh needs python3 for the verify gate's JSON parse.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Tell systemd we're running in a container so enable/start paths don't
# hang waiting for real boot linkage.
ENV container=docker \
    SYSTEMD_LOG_LEVEL=info