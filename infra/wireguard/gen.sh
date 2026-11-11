#!/bin/sh
set -eu
OUT="${REPO:-/repo}/infra/wireguard/out"
SITES="ubs escola centro horta abrigo"
HUB_FIBRA="10.250.1.10:51820"
HUB_4G="10.250.2.10:51820"

chave() {
  mkdir -p "$1"
  if [ ! -f "$1/private.key" ]; then
    umask 077
    wg genkey > "$1/private.key"
    wg pubkey < "$1/private.key" > "$1/public.key"
    echo "  chaves geradas: $(basename "$1")"
  else
    echo "  chaves existentes: $(basename "$1")"
  fi
}

chave "$OUT/hub"
HUB_PUB="$(cat "$OUT/hub/public.key")"
{
  echo "[Interface]"
  echo "Address = 10.99.0.1/24"
  echo "ListenPort = 51820"
  echo "PrivateKey = $(cat "$OUT/hub/private.key")"
} > "$OUT/hub/wg0.conf"
: > "$OUT/hub/peers.map"

n=11
for s in $SITES; do
  chave "$OUT/$s"
  pub="$(cat "$OUT/$s/public.key")"
  {
    echo
    echo "[Peer]"
    echo "PublicKey = $pub"
    echo "AllowedIPs = 10.99.0.$n/32"
  } >> "$OUT/hub/wg0.conf"
  echo "$pub $s 10.99.0.$n" >> "$OUT/hub/peers.map"
  {
    echo "[Interface]"
    echo "Address = 10.99.0.$n/32"
    echo "PrivateKey = $(cat "$OUT/$s/private.key")"
    echo
    echo "[Peer]"
    echo "PublicKey = $HUB_PUB"
    echo "AllowedIPs = 10.99.0.1/32"
    echo "Endpoint = $HUB_FIBRA"
    echo "PersistentKeepalive = 10"
  } > "$OUT/$s/wg0.conf"
  {
    echo "FIBRA=$HUB_FIBRA"
    echo "LTE=$HUB_4G"
    echo "HUB_PUB=$HUB_PUB"
    echo "TUNEL_IP=10.99.0.$n"
  } > "$OUT/$s/endpoints.env"
  n=$((n + 1))
done
chave "$OUT/admin"
pub="$(cat "$OUT/admin/public.key")"
{
  echo
  echo "[Peer]"
  echo "PublicKey = $pub"
  echo "AllowedIPs = 10.99.0.100/32"
} >> "$OUT/hub/wg0.conf"
echo "$pub admin 10.99.0.100" >> "$OUT/hub/peers.map"
{
  echo "[Interface]"
  echo "Address = 10.99.0.100/32"
  echo "PrivateKey = $(cat "$OUT/admin/private.key")"
  echo
  echo "[Peer]"
  echo "PublicKey = $HUB_PUB"
  echo "AllowedIPs = 10.99.0.1/32, 10.30.3.10/32"
  echo "Endpoint = $HUB_FIBRA"
  echo "PersistentKeepalive = 25"
} > "$OUT/admin/wg0.conf"
echo "Configurações WireGuard geradas em infra/wireguard/out/ (hub 10.99.0.1, espaços 10.99.0.11-15, admin 10.99.0.100)"
