#!/bin/sh
# Deploy from a Proxmox host into an LXC: CT=<id> scripts/deploy.sh. The CT never holds GitHub credentials.
set -eu
CT=${CT:?set CT=<container id>} DIR=/opt/wa-gateway
cd "$(dirname "$0")/.."
git ls-files | tar -cf - -T - | pct exec $CT -- sh -c "mkdir -p $DIR && tar -xf - -C $DIR"
pct exec $CT -- sh -c "cd $DIR && chmod +x scripts/*.sh && mkdir -p data/waha data/gateway webcache && chown 10001 data/gateway
  [ -f .env ] || { cp .env.example .env
    sed -i \"s/^WAHA_API_KEY=.*/WAHA_API_KEY=\$(openssl rand -hex 32)/; s/^WEBHOOK_HMAC_KEY=.*/WEBHOOK_HMAC_KEY=\$(openssl rand -hex 32)/\" .env
    chmod 600 .env; echo 'created .env with fresh secrets'; }
  [ -f clients.json ] || { echo '{}' > clients.json; echo 'created empty clients.json'; }
  [ -f media.json ] || { cp media.example.json media.json; echo 'created media.json from the example'; }"
echo "deployed to CT $CT:$DIR - then: pct exec $CT -- sh -c 'cd $DIR && docker compose up -d --build'"
