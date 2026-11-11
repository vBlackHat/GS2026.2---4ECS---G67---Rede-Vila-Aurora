#!/bin/sh
set -e
mkdir -p /etc/wireguard
cp /wg/wg0.conf /etc/wireguard/wg0.conf
chmod 600 /etc/wireguard/wg0.conf
wg-quick up wg0
install -m 600 /chaves/admin_ed25519 /root/.ssh/id_ed25519
install -m 644 /chaves/known_hosts /root/.ssh/known_hosts
echo "$(date +%Y-%m-%dT%H:%M:%S%z) ESTAÇÃO ADMIN: túnel 10.99.0.100 ativo; acesso administrativo só pelo bastion 10.30.3.10"
exec tail -f /dev/null
