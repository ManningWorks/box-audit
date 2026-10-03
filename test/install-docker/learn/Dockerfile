FROM box-audit-base:test

# The learn test (issue #71) needs ss (iproute2) for --init's port snapshot
# and cron for /etc/cron.d to be a real surface. Everything else (systemd,
# python3) is already in the base image. Keeping this image MINIMAL means
# the learn test's box state is fully controlled by the driver — no
# fail2ban/docker/containerd noise from the heavier seeded image.
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 \
        cron \
    && rm -rf /var/lib/apt/lists/*
