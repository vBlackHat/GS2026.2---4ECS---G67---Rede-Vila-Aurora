#!/bin/sh
set -e
log() { echo "$(date '+%Y-%m-%dT%H:%M:%S%z') $*"; }
mkdir -p /etc/wireguard
cp /wg/wg0.conf /etc/wireguard/wg0.conf
chmod 600 /etc/wireguard/wg0.conf
. /wg/endpoints.env
wg-quick up wg0
log "VPN: túnel $TUNEL_IP -> hub 10.99.0.1 via fibra ($FIBRA)"
nft delete table inet vila 2>/dev/null || true
nft -f /etc/vila/firewall.nft
log "FIREWALL: borda em negação por padrão; nenhuma conexão de entrada aceita"
atual=fibra
falhas=0
while true; do
  if ping -c1 -W2 10.99.0.1 >/dev/null 2>&1; then
    falhas=0
    if [ "$atual" = "4g" ] && ping -c1 -W2 "${FIBRA%:*}" >/dev/null 2>&1; then
      wg set wg0 peer "$HUB_PUB" endpoint "$FIBRA"
      atual=fibra
      log "LINK: fibra restabelecida; túnel voltou de 4g para fibra"
    fi
  else
    falhas=$((falhas + 1))
    log "LINK: hub sem resposta pelo túnel via $atual ($falhas/3)"
    if [ "$falhas" -ge 3 ]; then
      if [ "$atual" = "fibra" ]; then
        wg set wg0 peer "$HUB_PUB" endpoint "$LTE"
        atual=4g
        log "LINK: FAILOVER fibra -> 4g ($LTE)"
      else
        wg set wg0 peer "$HUB_PUB" endpoint "$FIBRA"
        atual=fibra
        log "LINK: 4g sem resposta; tentando fibra ($FIBRA)"
      fi
      falhas=0
    fi
  fi
  sleep 5
done
