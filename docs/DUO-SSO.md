# Real Duo OIDC SSO for agent-owner approval

Server code is implemented and tested against signed OIDC provider fixtures. A Duo tenant/application has not yet been created, so no live Duo SSO login has been verified. AI Cloud still runs the simulator. ISE remains out of scope.

## What the browser login approves

SPIRE proves the agent workload identity. Duo SSO proves its human owner's identity and MFA. The owner email is assigned by the enterprise administrator, not supplied by the agent. The verified owner login approves one pending agent session. The activity policy still determines priority, and the PCF call occurs during `/oauth/token`, not during the SSO callback.

Real mode uses these endpoints:

| Endpoint | Caller and purpose |
|---|---|
| `POST /duo/sso/requests` | Agent identity bearer; start pending owner approval and return `loginUrl` |
| `GET /duo/sso/start?request=...` | Owner's browser opens the short-lived, single-use link; redirect to Duo |
| `GET /duo/sso/callback` | Duo authorization-code redirect to the configured HTTPS URL |
| `GET /duo/sso/requests/<id>` | Same agent/session identity bearer; retrieve approval status |
| `POST /v1/admin/agents/<id>/owner` | Admin bearer; set owner email and revoke previous identities |
| `POST /oauth/token` | Existing client-authenticated activity request with `duo_approval_id` |

`/duo/push` and `/duo/admin/decide` are disabled in real mode. Old simulator approvals cannot be used after switching to real mode. There is no client-credentials grant for a human owner; this is an authorization-code browser flow.

## Create the Duo application

A tenant admin must first configure a working Duo SSO authentication source. Then add **Generic OIDC Relying Party**, labelled **SSO**, from the Application Catalog. Name it `PMBU Agent Identity Hackfest`. Grant the demo owner access and require MFA; do not configure MFA bypass for this application.

Enable Authorization Code, leave PKCE-only authentication unchecked (our server uses a client secret plus PKCE), and leave refresh tokens off. Enable `openid` and `email` scopes with the email mapped to the actual owner's trusted directory email. The user identity must match the administrator-assigned owner email; `hackfest-team` is not a valid real-SSO owner.

Register exactly:

```text
https://<browser-accessible-auth-host>/duo/sso/callback
```

The host needs trusted HTTPS terminating at a reverse proxy, forwarding to the foundation backend on 4191. This HTTPS endpoint is not provisioned yet. A loopback tunnel serving plain HTTP is not sufficient for this implementation's Secure browser cookie. The owner browser must reach the callback; a public-facing hostname is not required if that browser has private lab access. Preserve query parameters and cookies. Disable access logging of callback query strings and one-time login-link query strings.

Copy **Issuer**, **Client ID**, and **Discovery URL** from the Duo Metadata tab. The issuer is the application-specific SSO issuer, not the `api-...duosecurity.com` enrollment/API hostname. The library discovers endpoints from the issuer and verifies the discovered issuer. Store the client secret in protected server configuration, not chat or Git.

## Configure the service

The default mode remains `simulator`. For native use after the Duo app and HTTPS callback exist:

```sh
export PMBU_DUO_MODE=oidc
export DUO_ISSUER='https://<duo-sso-host>/oidc/<application-id>'
export DUO_CLIENT_ID='<application-client-id>'
export DUO_REDIRECT_URI='https://<browser-accessible-auth-host>/duo/sso/callback'
export DUO_CLIENT_SECRET_FILE='/protected/path/duo-client-secret'
npm ci
npm run start:foundation
```

The native secret file contains only the client secret, with restrictive permissions. `DUO_CLIENT_SECRET_FILE` takes precedence over `DUO_CLIENT_SECRET`. The AI Cloud Compose profile currently supports `DUO_CLIENT_SECRET` from its protected, Git-ignored `.env`; it does not automatically mount a secret file. Keep that file outside Git, mode 0600, and use the approved lab secret handling. Docker administrators can inspect container environment values.

For AI Cloud, set `PMBU_DUO_MODE`, `DUO_ISSUER`, `DUO_CLIENT_ID`, `DUO_CLIENT_SECRET`, and `DUO_REDIRECT_URI` in the protected `.env`, preserving the PCF endpoint and policy mapping. Then rebuild only the foundation:

```sh
sudo docker compose -p pmbu-aicloud -f compose.aicloud.yaml \
  up -d --build --no-deps identity-foundation
```

Do not switch the lab to real mode before these settings and HTTPS are ready. Missing configuration fails startup instead of silently falling back to the simulator. Build installs the pinned lockfile dependency graph with `npm ci --omit=dev`. The OIDC issuer and callback must use HTTPS; TLS validation is not disabled.

## Manual flow

1. Admin registers an agent with `owner:"<actual-owner-email>"`, or updates its existing owner using `POST /v1/admin/agents/<id>/owner` and body `{"owner":"<actual-owner-email>"}`. Owner updates invalidate the agent's existing identity sessions and their tokens, so fetch a fresh JWT-SVID and authenticate again afterward.
2. The Lattice workload obtains its JWT-SVID and calls `/foundation/spiffe/exchange` with `jwt_svid`, `agentIp`, and numeric `agentPort` as before.
3. Instead of `/duo/push`, call `/duo/sso/requests` with the identity bearer and matching IP/port:

```json
{"agentIp":"<actual-UE-data-plane-IP>","agentPort":45001}
```

Response includes `id`, `sessionId`, `source:"oidc"`, `status:"pending"`, `expiresAt`, and a one-time `loginUrl`. Share that link only with the intended owner. It does not contain the identity token. Merely obtaining or opening it does not approve the session.

4. The owner opens `loginUrl` in a browser, signs in through Duo, and completes MFA. The callback returns approval JSON, not raw Duo tokens. Only the configured directory owner can approve this session.
5. The agent polls `GET /duo/sso/requests/<id>` with the same identity bearer. Once approved, pass that `id` as `duo_approval_id` in the existing `/oauth/token` request. The RAR token includes `approval_source:"oidc"`, `owner_subject`, `owner_issuer`, and `mfa_verified:true`. PCF mapping remains background → downgrade and interactive/critical → boost.

The approval flow expires within 120 seconds and cannot outlive the identity session/JWT-SVID. If it expires, fetch fresh credentials and start again. A browser can have one pending login at a time because its secure login cookie is replaced by a new start. State is held in memory; a foundation restart invalidates pending browser links/callbacks. No refresh tokens or persistent human SSO session are created by our service.

## Validation and limits

Uses maintained `openid-client` with authorization code, S256 PKCE, nonce, state, explicit RS256 ID-token signature verification against the provider's JWKS, issuer/audience/expiry validation, and recent authentication checks. A Secure/HttpOnly/SameSite=Lax cookie binds the callback to the initiating browser. Links and callback state are single-use. The callback URL is reconstructed from trusted configuration, not forwarded Host headers.

The signed ID token must contain the administrator-assigned owner email and `amr` including `mfa`. Duo documents `mfa` for successful MFA and omits AMR on bypass. Missing AMR or an unexpected token shape fails closed; inspect tenant claim mapping and authentication policy rather than disabling the check. Email is matched against a trusted configured issuer's signed directory claim; the user cannot choose an arbitrary owner in the request.

46 local tests pass, including invalid signature, issuer, audience, nonce, expiry, MFA bypass, wrong owner, wrong browser, replay, denied login, inactive/changed-owner sessions, simulator bypass, and no PCF call after failed owner/MFA checks. These are fixture tests, not evidence of a real Duo tenant login. PCF still needs a verified real UE-flow POST and policy-lifetime/removal semantics.

Sources: [Duo Generic OIDC Relying Party](https://duo.com/docs/sso-oidc-generic), [Duo SSO authentication-context AMR values](https://duo.com/docs/sso), [openid-client](https://github.com/panva/openid-client).
