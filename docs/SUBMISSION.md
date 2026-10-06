# HF-2834 submission materials

Deadline from user-provided event requirements: Thursday, October 8, 2026, 9:00 PM local time (IST for this workspace). Jira and the event SharePoint page were inaccessible in this session. This file is a local draft, not an Epic update.

## What and why — three paragraphs for the Epic

Local AI agents will increasingly execute on phones, Raspberry Pis, laptops and deskside assistants. Their network importance depends on what they are doing: the same health-monitoring agent may perform a background model update and generate a life-critical alert. Our hack explores agent identity driven traffic prioritization, linking authenticated, temporary agent identities and activity-specific enterprise policies to a hosted connectivity decision interface for access networks, edge data centers and enterprise locations.

We implemented a working local Agent Identity Management prototype with administrator-controlled registration, short-lived signed runtime identities, activity grants, renewal, expiry, termination and revocation. The policy system assigns importance by agent profile and operation; agents cannot elevate traffic simply by supplying their own class. The gateway checks the current policy and identity lifecycle, authorizes a flow within its network context, and dispatches an application queue in priority order. The demo shows one health identity producing both background model-update traffic and a critical synthetic alert, while rejecting unauthorized escalation, mismatched flows and a revoked agent.

The result demonstrates the identity-to-priority control-plane contract that can connect enterprise identity/policy and hosted connectivity. The Docker foundation verifies real SPIRE-issued workload JWT-SVIDs, creates temporary identity sessions, simulates Duo approval, and issues signed activity-specific RAR QoS entitlements. Access, edge and enterprise contexts share policy concepts; the original prototype demonstrates application scheduling. Real Duo and ISE integration are out of scope. Trusted traffic-flow correlation, PCF integration and cellular QoS enforcement remain integration work for the team. Our evidence covers workload identity, priority authorization and application queue ordering, without claiming measured cellular performance or medical reliability.

## Links to add after publishing and recording

- Source code: **pending repository URL**. Local source: `/Users/arindamg/Cloud_Security/pmbu-agent-identity`.
- Supporting material: README, `docs/MANUAL-TESTING.md`, `docs/FOUNDATION.md`, `docs/API.md`, `docs/INTEGRATIONS.md`, `docs/PROMPTS.md`, `artifacts/demo-results.json`, and `artifacts/spire-results.json`.
- Webex / Vidcast recording: **pending 5–7-minute recording URL**.
- Recording password, if needed: **pending**.
- AI-generated video transcript: **pending actual video transcript**. The script below is not a transcript.

Do not publish `data/`, secrets, signing keys or token responses. Transcripts must be enabled before recording. Stop the recording completely rather than pausing it, wait for recording/link/password processing, verify access, and attach the generated transcript to the Epic before the deadline.

## Six-minute recording script

**0:00–0:45 — Problem.** Explain the proliferation of local agents and changing importance across activities. Give the health model-update versus alert example. State that the alert is synthetic and the prototype demonstrates identity authorization and application scheduling.

**0:45–1:30 — Architecture.** Show the registry → temporary identity → activity grant → hosted-connectivity decision → network adapter flow. Identify which components are real locally and which integrations are simulated. Explain why identity and activity are separate.

**1:30–2:30 — Live scenario.** Connect before recording so no secret is typed on camera. Run the access scenario. Point out that the health alert arrives fourth but dispatches first, booking follows, and background work comes last. Show that health alert and model update share one identity using the agent IDs in the audit.

**2:30–3:30 — Zero-trust checks.** Show the denied recipe-agent alert request, wrong-flow use, and revoked security identity. Explain short lifetimes and online gateway reevaluation. Do not scroll to the credential response panel.

**3:30–4:30 — Lifecycle and policy.** Show inventory and audit events. Explain renewal and activity expiry. Show the profile-to-operation rules and describe how a changed policy takes effect for an existing grant. Use the CLI evidence or test output if the activity has expired rather than implying stale grants remain usable.

**4:30–5:30 — Deployment contexts.** Run edge and enterprise scenarios. Explain that the same contract applies to each context, while real deployment needs separate enforcement adapters. For cellular, describe the operator integration boundary without claiming a configured 5QI or real bearer.

**5:30–6:00 — Results and next steps.** Show the 29 passing tests and token-free live SPIRE demo output. Summarize verified workload identity and priority authorization, with PCF/network integration pending and real Duo/ISE outside scope. Point to the source and interface documentation. Stop the recording.
