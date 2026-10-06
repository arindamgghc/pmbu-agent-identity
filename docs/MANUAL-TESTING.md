# Manual testing of SPIRE identity and activity priority

Run one block at a time in the same terminal. The walkthrough takes about 30–45 minutes and covers real SPIRE workload identity, simulated approval, activity-specific priority and identity termination. Only the final manual test commands mutate demo state; sourcing the setup file only loads credentials. Real Duo and ISE integration are outside this hack's scope. Network enforcement remains a connectivity-adapter integration.

The four containers are already running on Arindam's Mac. Do not bootstrap SPIRE again for each walkthrough. On a fresh teammate checkout, follow `FOUNDATION.md` first. Required tools: Docker Desktop, Node 20+, curl and jq.

## 1 Load credentials and check services

```sh
cd /Users/arindamg/Cloud_Security/pmbu-agent-identity
source examples/manual-env.sh
docker compose --profile spire ps
curl -sS "$HF_BASE/health" | jq
curl -sS "$HF_BASE/.well-known/oauth-authorization-server" | jq
curl -sS "$HF_BASE/.well-known/jwks.json" | jq
```

Expected: four running containers, foundation `healthy`, and health status `ok`. HTTP is published only on `127.0.0.1:4191`; SPIRE Server port 8081 is internal to Docker. The SPIRE Agent exposes a Unix socket rather than an HTTP endpoint. The workload client consumes that socket.

`HF_ADMIN` and `HF_SECRET` contain local credentials. Do not print them or enable shell tracing (`set -x`). The private state export is ignored by Git. All commands below display tokens as `[redacted]` or omit them; the shell retains originals for later calls.

## 2 Register and map only if needed

The existing live demo already has a security mapping. If setup reported an existing mapping, skip this block. Inspect the registry instead:

```sh
curl -sS "$HF_BASE/v1/admin/snapshot" \
  -H "Authorization: Bearer $HF_ADMIN" | jq '{agents,policy}'
```

For a fresh unmapped stack only:

```sh
HF_REGISTRATION=$(curl --fail-with-body -sS "$HF_BASE/v1/admin/agents" \
  -H "Authorization: Bearer $HF_ADMIN" -H 'Content-Type: application/json' \
  -d '{"name":"Manual security agent","deviceId":"spire-container-workload","profile":"security","owner":"demo-human"}')
printf '%s' "$HF_REGISTRATION" | jq '.enrollmentToken="[redacted]"'
HF_AGENT_ID=$(printf '%s' "$HF_REGISTRATION" | jq -r .agent.id)
jq -n --arg agentId "$HF_AGENT_ID" --arg spiffeId "$HF_SPIFFE" \
  '{agentId:$agentId,spiffeId:$spiffeId}' | \
  curl --fail-with-body -sS "$HF_BASE/foundation/admin/spiffe-mapping" \
  -H "Authorization: Bearer $HF_ADMIN" -H 'Content-Type: application/json' -d @- | jq
```

Expected: `201` registration and `200` mapping. Group/profile is assigned by the administrator; the SPIRE path alone does not assign priority. The enrollment token belongs to the alternative local identity flow and is not used here.

## 3 Fetch and understand a real JWT SVID

```sh
HF_SPIRE_OUTPUT=$(docker compose exec -T spire-client \
  /opt/spire/bin/spire-agent api fetch jwt \
  -audience pmbu-rar-issuer -spiffeID "$HF_SPIFFE")
HF_JWT_SVID=$(printf '%s\n' "$HF_SPIRE_OUTPUT" | \
  sed -n 's/^[[:space:]]*\(eyJ[^[:space:]]*\)$/\1/p')
printf '%s' "$HF_JWT_SVID" | node --input-type=module -e \
  'let s="";for await(const c of process.stdin)s+=c;console.log(JSON.stringify(JSON.parse(Buffer.from(s.split(".")[1],"base64url")),null,2))'
```

Expected decoded claims: `sub` is `spiffe://pmbu.demo/workloads/security`, `aud` includes `pmbu-rar-issuer`, and `exp` is in the future. Decoding displays claims; it does not verify their signature. Verification happens in the next call. The workload client runs as UID 10001, which the configured Unix workload attestor matches to the registration.

## 4 Exchange the SVID for a temporary identity session

```sh
HF_IDENTITY_RESPONSE=$(jq -n --arg svid "$HF_JWT_SVID" '{jwt_svid:$svid}' | \
  curl --fail-with-body -sS "$HF_BASE/foundation/spiffe/exchange" \
  -H 'Content-Type: application/json' -d @-)
printf '%s' "$HF_IDENTITY_RESPONSE" | jq '.token="[redacted]"'
HF_IDENTITY=$(printf '%s' "$HF_IDENTITY_RESPONSE" | jq -r .token)
```

Expected `200`, `identitySource: verified-jwt-svid`, a session ID and the source SPIFFE identity. Its expiration cannot exceed the source credential's expiration. If the SVID expires while you are reading, repeat steps 3 and 4. A new session requires a new approval.

## 5 Request approval and observe pending status

```sh
HF_PUSH_RESPONSE=$(curl --fail-with-body -sS "$HF_BASE/duo/push" \
  -H "Authorization: Bearer $HF_IDENTITY" \
  -H 'Content-Type: application/json' -d '{}')
printf '%s' "$HF_PUSH_RESPONSE" | jq
HF_PUSH_ID=$(printf '%s' "$HF_PUSH_RESPONSE" | jq -r .id)
```

Expected `201`, `status: pending`, `group: security`, and your current session ID. Approval expires in 120 seconds. Run steps 6–9 together within that window; if it expires, create a new push and rebuild the request in step 6.

## 6 Request a critical alert before approval

Build the request with synthetic flow and subscriber references:

```sh
HF_REQUEST=$(jq -n --arg identity "$HF_IDENTITY" --arg push "$HF_PUSH_ID" '{
  grant_type:"urn:ietf:params:oauth:grant-type:token-exchange",
  subject_token_type:"urn:ietf:params:oauth:token-type:jwt",
  subject_token:$identity,audience:"pmbu-pcf-adapter",duo_approval_id:$push,
  authorization_details:[{
    type:"urn:pmbu:authorization:network-qos",operation:"security_alert",
    network_context:"access",flow_id:"manual-alert-01",
    subscriber_id:"DEMO-SUBSCRIBER",pdu_session_id:"demo-session-1",
    flow:{src_ip:"192.0.2.10",dst_ip:"192.0.2.20",src_port:45000,dst_port:443,protocol:"tcp"}
  }]
}')
printf '%s' "$HF_REQUEST" | curl -sS -w '\nHTTP %{http_code}\n' \
  "$HF_BASE/oauth/token" --user "pmbu-agent-client:$HF_SECRET" \
  -H 'Content-Type: application/json' -d @-
```

Expected `403`, `invalid_grant`, and `Duo emulator approval required for this identity`. Having a valid identity alone does not authorize the requested priority.

## 7 Approve the simulated push as administrator

```sh
jq -n --arg push "$HF_PUSH_ID" '{push_id:$push,status:"approved"}' | \
  curl --fail-with-body -sS "$HF_BASE/duo/admin/decide" \
  -H "Authorization: Bearer $HF_ADMIN" -H 'Content-Type: application/json' -d @- | jq
```

Expected `200` and `status: approved`. This is an explicit emulator decision, not a real Duo Push. Keep the administrator action separate from the agent action when demonstrating it.

## 8 Obtain the signed critical entitlement

```sh
HF_RAR_RESPONSE=$(printf '%s' "$HF_REQUEST" | \
  curl --fail-with-body -sS "$HF_BASE/oauth/token" \
  --user "pmbu-agent-client:$HF_SECRET" -H 'Content-Type: application/json' -d @-)
printf '%s' "$HF_RAR_RESPONSE" | jq '.access_token="[redacted]"'
HF_RAR_TOKEN=$(printf '%s' "$HF_RAR_RESPONSE" | jq -r .access_token)
```

Expected `200`, `qos_tier: critical`, illustrative `5qi: 7`, `dscp: 46`, and lifetime at most 120 seconds. `flow_binding_verified: false` means these synthetic references have not been correlated to actual network traffic.

## 9 Compare a background activity and reject escalation

```sh
HF_BACKGROUND_REQUEST=$(printf '%s' "$HF_REQUEST" | jq \
  '.authorization_details[0] |= (.operation="model_update" | .flow_id="manual-update-01" | .flow.src_port=45001)')
HF_BACKGROUND_RESPONSE=$(printf '%s' "$HF_BACKGROUND_REQUEST" | \
  curl --fail-with-body -sS "$HF_BASE/oauth/token" \
  --user "pmbu-agent-client:$HF_SECRET" -H 'Content-Type: application/json' -d @-)
printf '%s' "$HF_BACKGROUND_RESPONSE" | jq '.access_token="[redacted]"'
printf '%s' "$HF_BACKGROUND_REQUEST" | jq '.authorization_details[0].qos_tier="critical"' | \
  curl -sS -w '\nHTTP %{http_code}\n' "$HF_BASE/oauth/token" \
  --user "pmbu-agent-client:$HF_SECRET" -H 'Content-Type: application/json' -d @-
```

Expected: the same identity receives `background`, `5qi: 9`, `dscp: 8` for the update. Explicitly asking for `critical` yields `403` with `invalid_authorization_details`. This is the activity-dependent importance demonstration.

## 10 Introspect and end the identity

```sh
printf '%s' "$HF_RAR_TOKEN" | jq -Rs '{token:.}' | \
  curl --fail-with-body -sS "$HF_BASE/oauth/introspect" \
  --user "pmbu-pcf-adapter:$HF_SECRET" -H 'Content-Type: application/json' -d @- | jq
```

Expected `active: true`, SPIRE workload ID in `sub`, critical tier and `enforcement: dry_run_only`. If the token expired while reading, refresh identity/approval and issue a new token before testing termination.

```sh
curl --fail-with-body -sS "$HF_BASE/v1/identities/end" \
  -H "Authorization: Bearer $HF_IDENTITY" -H 'Content-Type: application/json' -d '{}' | jq
printf '%s' "$HF_RAR_TOKEN" | jq -Rs '{token:.}' | \
  curl --fail-with-body -sS "$HF_BASE/oauth/introspect" \
  --user "pmbu-pcf-adapter:$HF_SECRET" -H 'Content-Type: application/json' -d @- | jq
```

Expected `ended: true`, followed by `active: false`. The registry entry remains active, so another walkthrough can start at step 3. No real network treatment is installed or removed by these calls.

## 11 Inspect the audit without exposing credentials

```sh
curl -sS "$HF_BASE/v1/admin/snapshot" \
  -H "Authorization: Bearer $HF_ADMIN" | jq '.audit[-15:]'
```

Look for `spiffe.exchanged`, `duo.push.pending`, `duo.push.approved`, `rar.issued`, and `identity.ended`. Rejection responses above show denials; they are not all recorded as audit events.

## 12 Optional wrong audience test

```sh
HF_WRONG_OUTPUT=$(docker compose exec -T spire-client \
  /opt/spire/bin/spire-agent api fetch jwt \
  -audience wrong-audience -spiffeID "$HF_SPIFFE")
HF_WRONG_SVID=$(printf '%s\n' "$HF_WRONG_OUTPUT" | \
  sed -n 's/^[[:space:]]*\(eyJ[^[:space:]]*\)$/\1/p')
jq -n --arg svid "$HF_WRONG_SVID" '{jwt_svid:$svid}' | \
  curl -sS -w '\nHTTP %{http_code}\n' "$HF_BASE/foundation/spiffe/exchange" \
  -H 'Content-Type: application/json' -d @-
```

Expected `401` and `Expired SVID or wrong audience`. A genuine SPIRE signature is insufficient when the credential targets a different audience.

## GitHub handoff after the walkthrough

Allow 30–45 minutes for the walkthrough, 15–20 minutes for fixes/questions, and 15–20 minutes to publish and verify the team can access the repository. The repository should contain source, tests, Compose configuration, diagrams and documentation. Runtime state, credentials, SVIDs, ZIP bundles and screenshots are excluded by `.gitignore`.

Before pushing:

```sh
npm test
docker compose --profile spire config --quiet
git status --short
git diff --cached --stat
git ls-files data foundation-data deploy/spire/runtime
```

The final command must print nothing. GitHub destination and team permissions must be resolved before publishing; a private repository link alone does not grant colleagues access. No repository push or team message is part of these manual test commands.
