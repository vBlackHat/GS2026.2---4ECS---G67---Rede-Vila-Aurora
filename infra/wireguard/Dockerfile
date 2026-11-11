FROM alpine:3.20
RUN apk add --no-cache wireguard-tools iproute2 iputils nftables bash tzdata
COPY gen.sh edge-entrypoint.sh hub-entrypoint.sh /usr/local/bin/
