#!/bin/sh
# AI Cloud server only: no join token or Lattice workload registration yet.
set -eu
cd "$(dirname "$0")/../.."
umask 077
mkdir -p deploy/spire/runtime
docker compose -p pmbu-aicloud -f compose.aicloud.yaml up -d --build
ready=0
for n in $(seq 1 30); do
  if docker compose -p pmbu-aicloud -f compose.aicloud.yaml exec -T spire-server \
    /opt/spire/bin/spire-server healthcheck >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
[ "$ready" -eq 1 ] || { echo 'SPIRE server not ready; inspect its logs.' >&2; exit 1; }
docker compose -p pmbu-aicloud -f compose.aicloud.yaml exec -T spire-server \
  /opt/spire/bin/spire-server bundle show -format pem > deploy/spire/runtime/bundle.pem.new
docker compose -p pmbu-aicloud -f compose.aicloud.yaml exec -T spire-server \
  /opt/spire/bin/spire-server bundle show -format spiffe > deploy/spire/runtime/bundle.json.new
chmod 755 deploy/spire/runtime
chmod 644 deploy/spire/runtime/bundle.pem.new deploy/spire/runtime/bundle.json.new
mv deploy/spire/runtime/bundle.pem.new deploy/spire/runtime/bundle.pem
mv deploy/spire/runtime/bundle.json.new deploy/spire/runtime/bundle.json
printf '%s\n' 'Central services started; public trust bundles exported. Lattice attestation is a separate step.'
