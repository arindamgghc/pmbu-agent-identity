# PCF and Duo SSO integration after the October 7 sync

## Implemented integration

Admin registration contains identity, owner, and enterprise profile; no IP or port. A workload fetches its JWT-SVID from the local SPIRE Agent, then calls `/foundation/spiffe/exchange` with `jwt_svid`, `agentIp`, and numeric `agentPort`. These fields describe its UE data connection. They are retained in its identity session, Duo simulator approval, and signed QoS token. SPIRE verifies the workload identity, not the caller-supplied flow association.

A session-bound Duo approval plus an authorized activity are required. With PCF enabled, `POST /oauth/token` authorizes the activity and makes an HTTP/2 prior-knowledge request to the configured PCF URL before returning the token and PCF result. Plain HTTP uses h2c, matching Abdullah's curl. No PCF call occurs solely on receiving a JWT-SVID, because the activity and owner approval have not yet been supplied.

The outbound JSON is exactly:

```json
{"agentIP":"192.0.2.1","agentPort":"1234","policy":"downgrade"}
```

`agentPort` is serialized as a string for this endpoint. QoS tier comes from enterprise activity policy; the caller cannot choose an arbitrary PCF instruction. Agent/session IDs, full flow tuple, and JWT stay in our service/token; the agreed three-field PCF API does not accept them. Confirm with Abdullah how protocol, NAT, subscriber/PDU-session binding, policy lifetime, and removal are handled before claiming complete per-flow enforcement.

The confirmed PCF instructions are `downgrade` and `boost`. The configured mapping is background → downgrade, interactive → boost, critical → boost. The service rejects other instruction values at startup.

```sh
export PMBU_PCF_ENDPOINT='http://10.8.102.208:18091/api/policy'
export PMBU_PCF_POLICIES='{"background":"downgrade","interactive":"boost","critical":"boost"}'
```

For native execution, restart `npm run start:foundation`. For AI Cloud, export these on that host and rebuild the container:

```sh
sudo -n env PMBU_PCF_ENDPOINT="$PMBU_PCF_ENDPOINT" PMBU_PCF_POLICIES="$PMBU_PCF_POLICIES" \
  docker compose -p pmbu-aicloud -f compose.aicloud.yaml up -d --build identity-foundation
```

Without `PMBU_PCF_ENDPOINT`, existing dry-run behavior remains. The laptop Compose profile does not forward these variables by default; use native execution for PCF tests or the AI Cloud profile in the lab.

Success adds `pcf` to the token response with `status:"api_accepted"`, HTTP status, sent IP/port/policy, and `networkEnforcementVerified:false`. The signed token says `enforcement:"pcf_requested"`; it does not certify PCF success. A non-2xx response or connection failure yields 502; timeout yields 504; missing mapping yields 503. Failed requests remove the provisional token from active introspection state. Requests time out after five seconds, responses are bounded, and there are no automatic retries. On timeout the network may already have applied the request; verify with Abdullah before retrying. Identity expiry/revocation does not currently remove a PCF policy; the removal API is not yet agreed.

All 46 local tests pass. HTTP/2 tests use a local mock and cover approval gating, exact payload, unsupported mapping, non-2xx rejection, and timeout. AI Cloud uses this mapping after successful simulated Duo approval and activity authorization. No real PCF POST with a valid UE flow has been verified yet; the HTTP/2 tests use a local mock. Synthetic test addresses must not be used as real UE flow references.

## Duo SSO setup pending tenant access/configuration

Real Duo SSO server code is implemented locally; AI Cloud still uses the simulator until tenant and HTTPS configuration are ready. See [Duo SSO setup](DUO-SSO.md). ISE remains out of scope. Duo SSO authenticates the human owner, while SPIRE authenticates the workload. The authentication server must bind a verified owner login to the pending agent session; enterprise activity policy determines QoS.

Proposed path for this Node service: Duo **Generic OIDC Relying Party**, authorization-code flow with PKCE. If the team requires SAML metadata instead, use **Generic SAML Service Provider** and a maintained SAML library; do not treat SAML metadata and OIDC discovery as interchangeable.

Tenant/application checklist (configuration work, not completed):

1. Use Abdullah's authorized trial tenant or the agreed enterprise tenant. Duo SSO needs a working authentication source and a test user who can access the application.
2. Create a Generic OIDC Relying Party named `PMBU Agent Identity Hackfest`. Enable authorization-code flow and `openid`/`email` scopes, and configure a policy requiring MFA for the demo user.
3. Agree the authentication server's browser-accessible HTTPS URL. Implemented callback path: `/duo/sso/callback`. Register the exact URL, with no wildcard.
4. Provide non-secret issuer/discovery URL and client ID. Store the client secret directly in protected server configuration, not Git or chat.
5. The local code implements browser start/callback with maintained OIDC tooling: short-lived single-use state tied to a pending agent approval, PKCE, nonce, signature/issuer/audience/expiry validation, and owner matching. A successful unrelated login must not approve another agent's session. Denied, missing, expired, or unverified logins must not trigger PCF.
6. Return an owner approval bound to the workload session, then authorize the requested activity and use the existing PCF caller. Keep simulator admin decisions unavailable in real-SSO mode.

Needed from team: tenant access, application protocol choice, discovery/metadata, callback origin, owner claim mapping, a successful PCF response example and trusted UE flow references. No real Duo app has been created and no live SSO result has been accepted yet.

Sources: [Duo Generic OIDC Relying Party](https://duo.com/docs/sso-oidc-generic), [Duo Generic SAML Service Provider](https://duo.com/docs/sso-generic).
