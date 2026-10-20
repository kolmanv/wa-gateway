#!/bin/sh
# Pin the WhatsApp Web build WAHA serves. Run on the server from /opt/wa-gateway.
# Usage: scripts/pin-webversion.sh [version]   (default: current build per wppconnect-team/wa-version)
set -eu
RAW=https://raw.githubusercontent.com/wppconnect-team/wa-version/main
v=${1:-$(curl -fsS $RAW/versions.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["currentVersion"])')}
mkdir -p webcache
curl -fsS "$RAW/html/$v.html" -o "webcache/$v.html"
sed -i "s/^WA_WEB_VERSION=.*/WA_WEB_VERSION=$v/" .env
curl -fsS $RAW/versions.json | python3 -c "import json,sys; print([x for x in json.load(sys.stdin)['versions'] if x['version']=='$v'])"
echo "pinned $v - apply with: docker compose up -d waha"
