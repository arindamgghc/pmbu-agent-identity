# Identity + Duo emulator + OAuth RAR foundation

Verified October 6, 2026: native API tests, both HTTP demos against Docker Compose, and the live SPIRE JWT-SVID → identity bridge → simulated Duo approval → signed RAR entitlement flow. Docker Desktop's corrupted volume metadata prevented startup; recreating its disposable virtual disk restored the engine. The existing port-4180 prototype is unchanged in behavior. This foundation uses port **4191**, native state in `foundation-data/`, and separate Compose volume state.

## Start and demo

```sh
cd /Users/arindamg/Cloud_Security/pmbu-agent-identity
npm run start:foundation
```

In another terminal:

```sh
npm run demo:foundation
sh examples/foundation-curl.sh
```

The curl script requires curl and jq, automatically registers a synthetic security agent, obtains a temporary identity, requests and approves a simulated human push, exchanges the identity for a signed RAR entitlement, and introspects it. It prints granted details rather than bearer tokens. The administrator approval in this test script is automated; it does not prove human presence or send a real Duo Push. For a manual demo, run the same steps separately and have the administrator perform `/duo/admin/decide`.

The Node demo additionally verifies pending approval rejection, background model-update authorization, escalation rejection, and immediate revocation. Evidence is saved in `artifacts/foundation-results.json` without secrets or bearer tokens. All 29 tests pass: 20 original tests plus 9 foundation tests.

## Docker Compose

On this Mac, add the bundled Docker tools to your shell path first (this also makes the credential helper available):

```sh
export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"
```

```sh
docker compose up -d --build identity-foundation
```

The identity service, simulated Duo approval and RAR issuer are modules of one foundation container, with persistent state and loopback-only published port 4191. Retrieve the **local test secrets** from the container state into a mode-0600 file if you want to run the host curl script:

```sh
umask 077
mkdir -p foundation-data
docker compose exec -T identity-foundation cat /app/state/state.json > foundation-data/compose-state.json
PMBU_STATE_FILE=foundation-data/compose-state.json sh examples/foundation-curl.sh
```

Do not start the native foundation and Compose foundation on the same port. Their state is separate. For validation while the native service is active, select a different host port in Compose or stop the native process first. Do not export `foundation-data/` or capture token/secrets panels in the recording.

## HTTP contract for Tim, Balaji and Abdullah

Base URL: `http://127.0.0.1:4191`. Loopback is not reachable from the lab or a colleague's laptop. Remote access needs an agreed endpoint with TLS and client authentication; no tunnel or public binding was created in this session.

| Endpoint | Authentication | Purpose |
|---|---|---|
| Existing `/v1/admin/agents`, `/v1/identities` | Existing admin / bootstrap credentials | Registry and local temporary identity |
| POST `/duo/push` | Agent identity bearer | Create pending simulated human approval; owner/group derived from registry |
| POST `/duo/admin/decide` | Admin bearer | `{push_id, status: "approved" or "denied"}` |
| POST `/oauth/token` | Basic `pmbu-agent-client:<local gatewayKey>` | Form-encoded token exchange plus `authorization_details` |
| GET `/.well-known/oauth-authorization-server` | None | Issuer, token endpoint, JWKS and supported RAR type |
| GET `/.well-known/jwks.json` | None | Public Ed25519 verification key only |
| POST `/oauth/introspect` | Basic `pmbu-pcf-adapter:<local gatewayKey>` | Form `{token}`; online active/inactive decision |
| POST `/foundation/admin/spiffe-mapping` | Admin bearer | Bind exact trusted SPIFFE subject to registered agent |
| POST `/foundation/spiffe/exchange` | JWT-SVID in JSON body | Verify trusted SPIRE credential, then issue short-lived local identity bridge |

Client names are role-checked, but the two OAuth clients share the prototype's local gateway secret. Issue separate per-client credentials for a real deployment. The original gateway endpoints are not modified to accept RAR tokens; an adapter must use the new JWKS and introspection contract.

Token request:

```json
{
  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "subject_token": "<temporary identity token>",
  "audience": "pmbu-pcf-adapter",
  "duo_approval_id": "<approved push ID>",
  "authorization_details": [{
    "type": "urn:pmbu:authorization:network-qos",
    "operation": "security_alert",
    "network_context": "access",
    "flow_id": "security-alert-01",
    "subscriber_id": "DEMO-SUBSCRIBER",
    "pdu_session_id": "demo-session-1",
    "flow": {"src_ip":"192.0.2.10","dst_ip":"192.0.2.20","src_port":45000,"dst_port":443,"protocol":"tcp"}
  }]
}
```

Form-encoded `authorization_details` is a JSON string; the service also accepts JSON for convenience. See the executable curl script and `authorization-details.schema.json`. The IPs and subscriber/session IDs above are synthetic examples, not lab values. The service validates the shape but does not attest this association.

Granted details appear both in the token response and the signed JWT's `authorization_details`. Top-level `5qi`, `dscp` and `qos_tier` are convenience claims. Access tokens are audience-restricted, expire within 120 seconds and cannot outlive their parent identity. Approval belongs to one runtime session, expires after 120 seconds, and cannot be reused by another identity. Activity importance is still policy-assigned, not chosen by the agent.

| Policy tier | Illustrative 5qi | Illustrative DSCP |
|---|---|---|
| background | 9 | 8 |
| interactive | 8 | 0 |
| critical | 7 | 46 |

**These values are demo placeholders, not an operator-approved mapping or a medical service guarantee.** Issued tokens carry `qos_mapping_status: "demo_only"`, `flow_binding_verified: false`, and `enforcement: "dry_run_only"`. Abdullah's adapter must keep these tokens in dry-run mode, establish trusted flow/subscriber correlation, and obtain an approved mapping before applying real PCF policy. Signing a QoS claim does not configure the network. Introspection becomes inactive on parent termination/revocation or policy-version change; offline signature checks alone cannot provide that immediate invalidation.

## Real SPIRE profile — verified live

Compose includes pinned official SPIRE 1.15.3 server/agent images and an unprivileged workload client. The SPIRE Agent shares the client PID namespace and uses the Unix workload attestor; the client is registered using UID 10001. This is a small isolated Linux-container demonstration, not proof of native macOS workload attestation. Bootstrap requires a working Docker engine and image downloads:

```sh
sh deploy/spire/bootstrap.sh
```

The script starts the server, exports public trust bundles, generates a single-use node join token, registers the workload and starts its agent/client. It does not print the join token. A one-shot initialization container sets data-volume ownership for SPIRE's non-root server. The node alias is `spiffe://pmbu.demo/nodes/demo-node`; the `/spire/` namespace is reserved. Initial bootstrap is intended for a fresh stack; on an existing attested stack, retain its registration/state and refresh public bundles rather than repeatedly reattesting.

Run the complete live demo after bootstrap. Refresh the private state export before each run so the demo can reuse the registered SPIFFE mapping:

```sh
umask 077
docker compose exec -T identity-foundation cat /app/state/state.json > foundation-data/compose-state.json
npm run demo:spire
```

The demo fetches actual JWT-SVIDs without printing them, verifies a correct audience, rejects a wrong audience, blocks pending approval, approves a simulated push, verifies the RAR signature using public JWKS, confirms the retained SPIFFE subject, and ends the identity to demonstrate immediate introspection invalidation. It leaves the registry entry active for repeat runs and writes token-free evidence to `artifacts/spire-results.json`. The approval is automated emulator behavior, not a real human Duo Push.

Fetch a JWT-SVID from the actual Workload API:

```sh
docker compose exec -T spire-client /opt/spire/bin/spire-agent api fetch jwt \
  -audience pmbu-rar-issuer -spiffeID spiffe://pmbu.demo/workloads/security
```

Create the local registry entry using the existing administrator API, then bind:

```json
{"agentId":"<registry ID>","spiffeId":"spiffe://pmbu.demo/workloads/security"}
```

Submit the fetched token as `{"jwt_svid":"<token>"}` to `/foundation/spiffe/exchange`. Native mode must set `SPIRE_BUNDLE_PATH=deploy/spire/runtime/bundle.json` before startup; Compose already mounts that file. Verification uses only that configured trust bundle, its JWT signing keys, the exact administrator-approved subject mapping and the `pmbu-rar-issuer` audience. JWT-provided key URLs are not trusted. The bridge retains the verified source SPIFFE ID and source expiration; renewal cannot extend past the source credential lifetime. Use its returned local identity token for the Duo/RAR sequence. Refresh the bundle after SPIRE signing-key rotation.

The JWT verifier passed generated-key tests for valid signature, trusted mapping, wrong audience, unmapped subject and expiration. The live demo additionally passed with SPIRE-issued ES256 JWT-SVIDs from the container Workload API. Real Duo and ISE integration are out of scope for this hack. The actual PCF adapter and trusted traffic-flow correlation remain team integration work.

## Standards and terminology

[RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html) defines structured authorization requests, token-request/response `authorization_details`, and the access-token claim. It does not standardize a “Rich JWT” format or our QoS fields. This implementation uses a custom PMBU RAR type with an [RFC 8693 token-exchange](https://www.rfc-editor.org/rfc/rfc8693.html) grant and a local approval parameter. It is a narrow hackfest OAuth profile, not a full authorization-code/OIDC server or a claim of full OAuth conformance. There are no refresh tokens, interactive browser consent endpoint or real Duo calls. SPIRE behavior and CLI references: [server](https://github.com/spiffe/spire/blob/main/doc/spire_server.md), [agent](https://github.com/spiffe/spire/blob/main/doc/spire_agent.md).
