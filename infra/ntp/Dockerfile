FROM alpine:3.20
RUN apk add --no-cache chrony tzdata \
 && mkdir -p /run/chrony /var/lib/chrony /var/log/chrony \
 && chown -R chrony:chrony /run/chrony /var/lib/chrony /var/log/chrony
ENTRYPOINT ["chronyd", "-d", "-x", "-f", "/etc/chrony/chrony.conf"]
