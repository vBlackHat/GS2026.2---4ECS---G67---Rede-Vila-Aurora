#!/bin/sh
set -e
SRC=/mosquitto/certs-ro
DST=/mosquitto/tls
mkdir -p "$DST"
for f in ca-chain.crt broker.crt crl.pem; do
  cp "$SRC/$f" "$DST/$f"
  chmod 644 "$DST/$f"
done
cp "$SRC/broker.key" "$DST/broker.key"
cp "$SRC/acl" "$DST/acl"
chmod 600 "$DST/broker.key" "$DST/acl"
chown -R mosquitto:mosquitto "$DST"
chmod 700 "$DST"
chown -R mosquitto:mosquitto /mosquitto/data /mosquitto/log 2>/dev/null || true
exec /usr/sbin/mosquitto -c /mosquitto/config/mosquitto.conf
