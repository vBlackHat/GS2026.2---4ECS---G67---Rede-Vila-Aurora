#!/bin/sh
set -e
for rede in 10.30.1.0/24 10.30.2.0/24 10.99.0.0/24; do
  ip route replace "$rede" via 10.30.3.254
done
install -m 600 /segredos/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key
install -m 644 /segredos/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_ed25519_key.pub
install -d -m 700 -o admin -g admin /home/admin/.ssh
install -m 600 -o admin -g admin /segredos/admin_ed25519.pub /home/admin/.ssh/authorized_keys
umask 077
{
  tr -d '\r\n' < /segredos/totp.secret
  printf '\n" RATE_LIMIT 3 30\n" WINDOW_SIZE 3\n" DISALLOW_REUSE\n" TOTP_AUTH\n'
} > /home/admin/.google_authenticator
chown admin:admin /home/admin/.google_authenticator
mkdir -p /run/sshd
echo "$(date +%Y-%m-%dT%H:%M:%S%z) BASTION: SSH em 10.30.3.10:22 (chave ed25519 + TOTP); rotas para svc, ops e túnel via firewall 10.30.3.254"
exec setpriv --bounding-set -net_admin sh -c '/usr/sbin/sshd -D -e 2>&1 | while IFS= read -r l; do printf "%s %s\n" "$(date +%Y-%m-%dT%H:%M:%S%z)" "$l"; done'
