FROM alpine:3.20
RUN apk add --no-cache wireguard-tools iproute2 iputils openssh-client tzdata
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY codigo /usr/local/bin/codigo
COPY ssh_config /root/.ssh/config
RUN chmod 755 /usr/local/bin/codigo && chmod 700 /root/.ssh && chmod 600 /root/.ssh/config
ENTRYPOINT ["/bin/sh", "/usr/local/bin/entrypoint.sh"]
