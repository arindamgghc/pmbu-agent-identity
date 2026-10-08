#!/bin/sh
# Lab test workload only. SPIRE Server remains on AI Cloud.
set -eu
cd "$(dirname "$0")/../.."
: "${SPIRE_JOIN_TOKEN:?Supply a fresh Lattice node join token securely}"
test -s deploy/spire/runtime/bundle.pem
DOCKER=${DOCKER:-docker}
for name in pmbu-lattice-spire-agent pmbu-lattice-spire-client; do
 if "$DOCKER" container inspect "$name" >/dev/null 2>&1; then
  echo "$name already exists; inspect its state before bootstrapping again." >&2
  exit 1
 fi
done
"$DOCKER" build -t pmbu-lattice-spire-client:1.15.3 -f deploy/spire/Dockerfile.client .
"$DOCKER" volume create pmbu-lattice-spire-data >/dev/null
"$DOCKER" volume create pmbu-lattice-spire-sockets >/dev/null
"$DOCKER" run --rm --user 0:0 --entrypoint /bin/sh \
 -v pmbu-lattice-spire-data:/state \
 pmbu-lattice-spire-client:1.15.3 -c 'chown 1000:1000 /state'
"$DOCKER" run -d --name pmbu-lattice-spire-client --restart unless-stopped \
 --user 10001:10001 -v pmbu-lattice-spire-sockets:/tmp/spire-agent/public \
 pmbu-lattice-spire-client:1.15.3 >/dev/null
"$DOCKER" run -d --name pmbu-lattice-spire-agent --restart unless-stopped \
 --pid=container:pmbu-lattice-spire-client \
 -v "$PWD/deploy/spire/agent.lattice.conf:/opt/spire/conf/agent.conf:ro" \
 -v "$PWD/deploy/spire/runtime:/opt/spire/bootstrap:ro" \
 -v pmbu-lattice-spire-data:/opt/spire/data \
 -v pmbu-lattice-spire-sockets:/tmp/spire-agent/public \
 ghcr.io/spiffe/spire-agent:1.15.3 \
 -config /opt/spire/conf/agent.conf -joinToken "$SPIRE_JOIN_TOKEN" >/dev/null
unset SPIRE_JOIN_TOKEN
for n in $(seq 1 30); do
 if "$DOCKER" exec pmbu-lattice-spire-agent /opt/spire/bin/spire-agent healthcheck >/dev/null 2>&1; then
  echo 'Lattice SPIRE Agent is healthy; test workload uses UID 10001.'
  exit 0
 fi
 sleep 1
done
echo 'Agent did not become healthy; inspect its logs.' >&2
exit 1
