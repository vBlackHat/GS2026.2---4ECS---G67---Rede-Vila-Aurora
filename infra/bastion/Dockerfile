FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server libpam-google-authenticator iproute2 netcat-openbsd tzdata \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -s /bin/bash admin \
 && usermod -p '*' admin \
 && rm -f /etc/ssh/ssh_host_* \
 && mkdir -p /run/sshd
COPY sshd_config /etc/ssh/sshd_config
COPY pam-sshd /etc/pam.d/sshd
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/bin/sh", "/usr/local/bin/entrypoint.sh"]
