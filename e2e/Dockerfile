FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    cron \
    sudo \
    net-tools \
    procps \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Set up sshd_config for testing
RUN mkdir -p /run/sshd && \
    echo "PasswordAuthentication no" >> /etc/ssh/sshd_config && \
    echo "PermitRootLogin no" >> /etc/ssh/sshd_config && \
    echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config

# Create a known cron job
RUN echo "0 * * * * root /usr/bin/echo heartbeat" > /etc/cron.d/heartbeat

# Copy trapline binary
COPY trapline /usr/local/bin/trapline
RUN chmod 755 /usr/local/bin/trapline

# Create state directories (normally install does this)
RUN mkdir -p /etc/trapline /var/lib/trapline/baselines /var/lib/trapline/state /var/log/trapline

# Keep container alive
CMD ["sleep", "infinity"]
