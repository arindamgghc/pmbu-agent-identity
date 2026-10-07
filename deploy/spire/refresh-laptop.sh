#!/bin/sh
# Existing laptop demo only; never use for AI Cloud or Lattice.
set -eu
cd "$(dirname "$0")/../.."
DOCKER=${DOCKER:-docker}
umask 077
"$DOCKER" compose exec -T spire-server /opt/spire/bin/spire-server healthcheck >/dev/null
mkdir -p deploy/spire/runtime
"$DOCKER" compose exec -T spire-server /opt/spire/bin/spire-server bundle show -format pem > deploy/spire/runtime/bundle.pem.new
"$DOCKER" compose exec -T spire-server /opt/spire/bin/spire-server bundle show -format spiffe > deploy/spire/runtime/bundle.json.new
chmod 755 deploy/spire/runtime
chmod 644 deploy/spire/runtime/bundle.pem.new deploy/spire/runtime/bundle.json.new
mv deploy/spire/runtime/bundle.pem.new deploy/spire/runtime/bundle.pem
mv deploy/spire/runtime/bundle.json.new deploy/spire/runtime/bundle.json
if ! "$DOCKER" compose exec -T spire-agent /opt/spire/bin/spire-agent healthcheck >/dev/null 2>&1; then
  SPIRE_JOIN_TOKEN=$("$DOCKER" compose exec -T spire-server /opt/spire/bin/spire-server token generate \
    -spiffeID spiffe://pmbu.demo/nodes/demo-node | sed -n 's/^Token: //p')
  [ -n "$SPIRE_JOIN_TOKEN" ] || { echo 'Could not obtain a join token.' >&2; exit 1; }
  export SPIRE_JOIN_TOKEN
  "$DOCKER" compose --profile spire up -d --no-deps spire-agent
  unset SPIRE_JOIN_TOKEN
fi
for n in $(seq 1 30); do
  if "$DOCKER" compose exec -T spire-agent /opt/spire/bin/spire-agent healthcheck >/dev/null 2>&1; then
    echo 'Laptop SPIRE Agent ready; public trust bundles refreshed.'
    exit 0
  fi
  sleep 1
done
echo 'Laptop SPIRE Agent not ready; inspect compose logs.' >&2
exit 1
