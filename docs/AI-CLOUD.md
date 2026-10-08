# AI Cloud central service deployment

Deployed and verified on October 6, 2026. The central services run in `/home/train3/pmbu-agent-identity` on AI Cloud `10.8.102.52`, under Compose project `pmbu-aicloud`. Fresh cloud-only persistent state and signing keys were generated. Laptop runtime state was not copied.

| Component | Published interface | Verification |
|---|---|---|
| Identity registry, Duo simulator and RAR issuer | `10.8.102.52:4191` on the lab interface; also `127.0.0.1:4191` | HTTP health and foundation demo passed |
| SPIRE Server | `10.8.102.52:8081` | SPIRE healthcheck passed |
| SPIRE data initializer | No port; exits after setting volume ownership | Exited successfully |

The foundation and SPIRE Server have `restart: unless-stopped` and dedicated named volumes. The SPIRE Agent and workload client are not deployed on AI Cloud. ISE remains out of scope. Real Duo SSO code is implemented locally, with tenant configuration and HTTPS setup still pending; AI Cloud continues in simulator mode. See [Duo SSO setup](DUO-SSO.md). PCF integration is enabled with background → downgrade and interactive/critical → boost; live UE-flow enforcement verification remains pending. See [PCF and Duo integration](PCF-DUO-INTEGRATION.md). A test SPIRE Agent/workload is now attested on Lattice at 10.8.96.25 with subject spiffe://pmbu.demo/workloads/lattice/security. Agent-1/Agent-2 registrations and verification of live PCF treatment remain separate work.

## Direct access from Lattice

The foundation API is now published on AI Cloud's private lab address. From Lattice:

```sh
curl --max-time 5 http://10.8.102.52:4191/health
curl http://10.8.102.52:4191/.well-known/oauth-authorization-server
curl http://10.8.102.52:4191/.well-known/jwks.json
```

Use `http://10.8.102.52:4191` as the base URL for identity, Duo simulator, token issuance and introspection calls. This is plain HTTP for the lab; credentials and tokens are unencrypted on this path. The service is not bound to all interfaces or published through the public jumphost address. SPIRE port 8081 continues to use TLS/gRPC.

## Access the foundation from your Mac through SSH

The current session has opened an SSH tunnel at `http://127.0.0.1:14191`. This points to AI Cloud, while your original laptop prototype stays on port 4191. Health, metadata and JWKS are accessible without credentials:

```sh
curl http://127.0.0.1:14191/health
curl http://127.0.0.1:14191/.well-known/oauth-authorization-server
curl http://127.0.0.1:14191/.well-known/jwks.json
```

If the tunnel closes, run the following in a terminal and leave it running. Do not start a second copy while port 14191 is occupied:

```sh
ssh -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 \
  -L 127.0.0.1:14191:127.0.0.1:24191 \
  -p 2264 abdullal@38.122.253.90 \
  'ssh -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 \
   -N -L 127.0.0.1:24191:127.0.0.1:4191 train3@10.8.102.52'
```

The two forwards use the jumphost's existing SSH access to AI Cloud. This optional path carries HTTP traffic inside SSH. Port 24191 is loopback-only on the jumphost.

The configured OAuth issuer is now `http://10.8.102.52:4191`, matching the shared lab endpoint. Clients should configure this issuer and the `pmbu-pcf-adapter` audience explicitly. Requests made through the SSH tunnel or AI Cloud loopback still receive tokens carrying this lab issuer. RAR tokens issued under the former `http://127.0.0.1:14191` issuer fail current introspection; request new entitlements. Registry state, identity sessions, credentials and signing keys are preserved.

## Inspect and manage the central services

Connect to the jumphost, then use its shortcut:

```sh
ssh -p 2264 abdullal@38.122.253.90
aicloud
cd ~/pmbu-agent-identity
```

Read status and logs:

```sh
sudo docker compose -p pmbu-aicloud -f compose.aicloud.yaml ps
sudo docker compose -p pmbu-aicloud -f compose.aicloud.yaml logs --tail 30 identity-foundation spire-server
curl http://127.0.0.1:4191/health
sudo docker compose -p pmbu-aicloud -f compose.aicloud.yaml exec -T spire-server \
  /opt/spire/bin/spire-server healthcheck
```

Restart a service while preserving state:

```sh
sudo docker compose -p pmbu-aicloud -f compose.aicloud.yaml restart identity-foundation
```

After changing source/configuration, rebuild and refresh public bundles with:

```sh
sudo sh deploy/spire/bootstrap-server.sh
```

The server-only bootstrap script never starts a local SPIRE Agent and never generates a node join token. Avoid `down -v`: it deletes persistent identity and SPIRE state.

## Manual testing on AI Cloud

The laptop manual walkthrough's `manual-env.sh` reads laptop state, so do not use it to load AI Cloud credentials. Run authenticated manual calls in your SSH session on AI Cloud, keeping cloud credentials there. Initialize these variables on the VM:

```sh
cd ~/pmbu-agent-identity
HF_BASE=http://127.0.0.1:4191
HF_ADMIN=$(sudo docker compose -p pmbu-aicloud -f compose.aicloud.yaml exec -T \
  identity-foundation node -e 'console.log(JSON.parse(require("fs").readFileSync("/app/state/state.json","utf8")).adminKey)')
HF_SECRET=$(sudo docker compose -p pmbu-aicloud -f compose.aicloud.yaml exec -T \
  identity-foundation node -e 'console.log(JSON.parse(require("fs").readFileSync("/app/state/state.json","utf8")).gatewayKey)')
```

These variables read only the required credentials and do not export the full state or signing key. Do not print the variables or enable shell tracing. Use the request bodies in `FOUNDATION.md`. The complete SPIRE manual flow additionally requires an attested Lattice Agent and workload registration, which are not created by this server deployment.

## Lattice handoff

Confirmed from `train1@10.8.102.55` (hostname `trainlatt3`):

```sh
nc -vz -w 5 10.8.102.52 8081
```

The TCP connection succeeded. This verifies reachability, not successful SPIRE Agent attestation.

The next setup needs:

1. A SPIRE Agent on Lattice with server address `10.8.102.52`, server port `8081`, and trust domain `pmbu.demo`.
2. AI Cloud's public X.509 trust bundle from `deploy/spire/runtime/bundle.pem` transferred to Lattice through the trusted SSH connection.
3. A short-lived single-use join token generated on AI Cloud and supplied securely to the Lattice Agent.
4. Separate workload registrations/selectors for AI agent-1 and AI agent-2, followed by registry-to-SPIFFE mappings in the foundation.
5. Configure the foundation base URL and issuer as `http://10.8.102.52:4191` for direct lab access, and agree the RAR-to-flow handoff with Abdullah's adapter. Use SSH tunneling or add TLS when encrypted access is required.

Public bundles are exported at `deploy/spire/runtime/bundle.pem` and `bundle.json`; the foundation reads the JSON bundle. Refresh them when SPIRE's signing keys rotate. Cloud private keys and credentials stay in Docker volume state. Token-free foundation validation evidence is stored in `artifacts/aicloud-results.json` in the source workspace and `/app/state/aicloud-results.json` in the cloud foundation container.
