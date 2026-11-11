#!/bin/sh
set -e
log() { echo "$(date '+%Y-%m-%dT%H:%M:%S%z') $*"; }
mkdir -p /etc/wireguard
cp /wg/wg0.conf /etc/wireguard/wg0.conf
chmod 600 /etc/wireguard/wg0.conf
wg-quick up wg0
log "VPN: hub ativo em 10.99.0.1, porta 51820 (fibra 10.250.1.10, 4g 10.250.2.10)"
nft delete table inet vila 2>/dev/null || true
nft -f /etc/vila/firewall.nft
log "FIREWALL: hub em negação por padrão; zonas iot (túnel), svc 10.30.1.0/24, ops 10.30.2.0/24, admin 10.30.3.0/24"
nome() { awk -v k="$1" '$1 == k { print $2 }' /wg/peers.map; }
anterior=""
while true; do
  atual="$(wg show wg0 endpoints)"
  if [ "$atual" != "$anterior" ]; then
    echo "$atual" | while read -r pk ep; do
      [ -n "$pk" ] && log "VPN: peer $(nome "$pk") endpoint $ep"
    done
    anterior="$atual"
  fi
  sleep 5
done
