# Team integration contract

Base URL: `http://127.0.0.1:4180`. JSON request bodies require `Content-Type: application/json`. Every credential goes in `Authorization: Bearer <credential>` except the activity token passed to the gateway, which is in the JSON body. The gateway must authenticate separately using its gateway key. Secrets are issued once to the caller and never included in snapshots or audit responses.

| Method | Path | Credential | Body / result |
|---|---|---|---|
| GET | `/health` | None | Liveness |
| GET | `/v1/admin/snapshot` | Admin key | Inventory, live lifecycle flags, policy, audit, integration labels |
| POST | `/v1/admin/agents` | Admin key | `{name, deviceId, profile, owner?}` → `{agent, enrollmentToken, enrollmentExpiresAt}` |
| POST | `/v1/admin/agents/:id/status` | Admin key | `{status: "active" \| "suspended" \| "revoked"}` |
| PUT | `/v1/admin/policy` | Admin key | `{rules: {recipe: {...}, travel: {...}, health: {...}, security: {...}}}` |
| POST | `/v1/identities` | Enrollment token | `{agentId, ttlSeconds?}` → `{token, agentId, sessionId, spiffeId, expiresAt}` |
| POST | `/v1/identities/renew` | Identity token | `{ttlSeconds?}` → new token / expiry |
| POST | `/v1/identities/end` | Identity token | `{}` → identity and all its activities become inactive |
| POST | `/v1/activities` | Identity token | `{operation, context, flowId, ttlSeconds?}` → `{token, activityId, trafficClass, expiresAt}` |
| POST | `/v1/activities/end` | Activity token | `{}` → end that activity only |
| POST | `/v1/gateway/evaluate` | Gateway key | `{token: activityToken, context, flowId}` → current policy decision |
| POST | `/v1/gateway/dispatch` | Gateway key | `{jobs: [{token, context, flowId}, ...]}` → ordered dispatched decisions and denials |
| POST | `/v1/gateway/feedback` | Gateway key | `{agentId, kind: "observation" \| "policy_violation", detail}` → recorded observation; no automatic suspension |
| POST | `/v1/demo` | Admin key | `{context: "access" \| "edge" \| "enterprise"}` → demo evidence |

Times are integer Unix seconds. Default/max identity TTL is 600 seconds; default/max activity TTL is 120 seconds. Enrollment TTL is 300 seconds. Activities never exceed the current parent expiry, and renewal does not extend existing activities. Revocation is terminal. Suspension invalidates all current sessions; reactivation does not resurrect old credentials. Register a replacement agent to bootstrap again in this small prototype.

The supported policy classes are `background`, `interactive`, `critical`. Rules may add/remove operations, but must retain the four profile keys. Profiles are administrator assigned. Clients cannot choose their class by supplying `trafficClass` or `profile` in the activity request. Authorization is operation-based; it does not prove that an alert is genuine.

Example decision:

```json
{
  "allow": true,
  "agentId": "<registered-agent-id>",
  "activityId": "<activity-id>",
  "operation": "health_alert",
  "context": "access",
  "flowId": "health-flow-01",
  "trafficClass": "critical",
  "rank": 3,
  "dscp": 46,
  "queue": "critical",
  "policyVersion": 1,
  "validUntil": 1790942806,
  "enforcement": "application-queue-demo",
  "cellular": "operator mapping required"
}
```

The response is online authorization, not a signed offline entitlement. `validUntil` is an upper bound on token validity, not permission to cache through revocation or policy updates. Reevaluate at enforcement. This prototype gateway always validates on arrival and dispatch; a real distributed gateway needs short cache TTLs plus invalidation or continuous online evaluation.

Errors use `{error: "reason"}` with 400 for invalid input, 401 for credentials/expiry/inactive identity, 403 for disallowed operation or mismatched flow/context, 404 for missing records/routes, 409 for reversing revocation, 413 for oversize payloads, and 415 for non-JSON bodies. Batch dispatch returns individual denials in its successful response. Online gateway evaluation audits allowed and denied requests.

`demo-client.js` is an executable example of the full role-separated HTTP flow. The flow ID is currently caller supplied and a logical label. Before connecting real packets, the gateway teammate must replace it with a trustworthy connection binding established by a local proxy/sidecar or attested OS process/network mapping.
