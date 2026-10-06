#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
DOCKER=${DOCKER:-docker}
command -v "$DOCKER" >/dev/null
umask 077
mkdir -p deploy/spire/runtime
"$DOCKER" compose --profile spire up -d --build spire-server
ready=0
for n in $(seq 1 30); do
 if "$DOCKER" compose exec -T spire-server /opt/spire/bin/spire-server healthcheck >/dev/null 2>&1; then ready=1; break; fi
 sleep 1
done
[ "$ready" -eq 1 ] || { echo 'SPIRE server not ready; inspect compose logs.' >&2; exit 1; }
"$DOCKER" compose exec -T spire-server /opt/spire/bin/spire-server bundle show -format pem > deploy/spire/runtime/bundle.pem
"$DOCKER" compose exec -T spire-server /opt/spire/bin/spire-server bundle show -format spiffe > deploy/spire/runtime/bundle.json
SPIRE_JOIN_TOKEN=$("$DOCKER" compose exec -T spire-server /opt/spire/bin/spire-server token generate -spiffeID spiffe://pmbu.demo/nodes/demo-node | sed -n 's/^Token: //p')
[ -n "$SPIRE_JOIN_TOKEN" ] || { echo 'Could not parse join token.' >&2; exit 1; }
export SPIRE_JOIN_TOKEN
"$DOCKER" compose exec -T spire-server /opt/spire/bin/spire-server entry create \
 -parentID spiffe://pmbu.demo/nodes/demo-node \
 -spiffeID spiffe://pmbu.demo/workloads/security -selector unix:uid:10001 >/dev/null
# Public trust bundles must be readable by the unprivileged issuer; never export a signing key.
chmod 755 deploy/spire/runtime
chmod 644 deploy/spire/runtime/bundle.pem deploy/spire/runtime/bundle.json
"$DOCKER" compose --profile spire up -d --build spire-client spire-agent
unset SPIRE_JOIN_TOKEN
printf '%s\n' 'SPIRE configured. Wait for agent attestation, then fetch a workload JWT-SVID:'
printf '%s\n' 'docker compose exec -T spire-client /opt/spire/bin/spire-agent api fetch jwt -audience pmbu-rar-issuer -spiffeID spiffe://pmbu.demo/workloads/security'
