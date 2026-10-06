# Integration boundaries and four-person team split

| Owner | Deliverable | Contract with identity service |
|---|---|---|
| You: identity / policy | Registration, identity lifecycle, activity authorization, profile policy, audit | This repository's HTTP API |
| Local agents teammate | Workloads on laptop / Pi / phone / assistant; background update and alert activities | Bootstrap once, retain identity locally, request an activity token for each operation |
| Connectivity / network teammate | Bind identity to observed connection, map class to access/edge/enterprise treatment | Authenticate gateway, evaluate activity token with matching context and flow, enforce current decision |
| Demo / monitoring teammate | Queue / congestion demonstration, monitoring observations, recording and submission evidence | Submit authenticated feedback, inspect token-free snapshot and CLI results |

## SPIFFE / SPIRE

The registry identifies an accountable agent; the runtime session identifies an ephemeral workload instance. Changing operation does not require changing that instance ID. Activity grants add short-lived authorization so the same identity can simultaneously update its model at low priority and send an alert at high priority.

To replace the issuer, attest the node and workload through SPIRE, register selectors, obtain an SVID through the Workload API, then verify it against the trust bundle and bind its SPIFFE ID to the registry entry. Use distinct audiences for exchanged activity/connection authorization. Do not feed this prototype's JWT into a real SVID validator: it is not an SVID.

Sources: [SPIRE concepts](https://spiffe.io/docs/latest/spire-about/spire-concepts/) and [SPIFFE JWT-SVID](https://spiffe.io/docs/latest/spiffe-specs/jwt-svid/).

## Enterprise policy / Duo

All profiles and class rules are presently administered locally. Integrate enterprise approval, ownership, device posture and group membership through the team's actual authorized enterprise APIs. Persist authoritative policy provenance and approval evidence instead of trusting an agent's self-report. Keep the issuer separate from administrator authentication.

The documented [Duo Auth API](https://duo.com/docs/authapi) supports user MFA, so it can be used in a human administrator/owner workflow. This prototype does not claim that it issues agent SVIDs or supplies a live Duo agent-priority policy. An additional agent-specific enterprise product/API requires confirmation from the team and product documentation before implementation.

## Hosted connectivity / access

The gateway decision is class/rank/queue/DSCP intent. It must be bound to an actual observed flow using a trusted endpoint proxy, mTLS identity, or workload-aware gateway. For cellular, the operator/connectivity teammate must choose supported QoS mechanisms and authorize the relevant flow; DSCP by itself does not provision a cellular QoS flow. No 5QI value is implied here.

## Edge and enterprise

Translate the same decision contract into the actual edge proxy, router or host scheduler. Choose class mappings with the network owner; implement enforcement, expiry, revocation invalidation, audit and fairness/rate limits. Keep marking under trusted gateway control rather than accepting arbitrary endpoint markings.

## Behavior feedback

A `policy_violation` observation is recorded for human review. Network observations cannot establish semantic truth of encrypted agent activities. Volume, destinations, frequency and posture can support anomaly decisions but should not silently turn a legitimate life-critical operation into background traffic without an explicit reviewed policy. This demo deliberately leaves that decision to the administrator.
