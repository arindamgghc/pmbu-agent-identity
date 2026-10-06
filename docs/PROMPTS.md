# Prompt and build provenance

This is a concise record of the user requirements and implementation choices, not a full AI conversation transcript or a video transcript.

## User requirements used

- PMBU Hackfest HF-2834: Agent Identity driven network traffic prioritization.
- A four-person team; this component is Agent Identity Management from the supplied architecture diagram.
- Build a working identity-service prototype.
- Local agents may run on phones, Raspberry Pis, laptops and deskside assistants.
- Agent importance changes with the activity: background work versus life-critical alerts.
- Temporary identities may follow enterprise zero-trust lifecycle choices and SPIFFE/SPIRE patterns.
- Demonstrate the interface between enterprise identity/policy, hosted connectivity, and access, edge and enterprise network prioritization.
- Epic submission requires a what/why description, source and supporting materials, a 5–7-minute Webex/Vidcast recording with transcripts enabled, and the generated video transcript.

## Implementation choices made by Codex

- Isolated folder beside an existing Duo agent demo; existing demo was not modified.
- Dependency-free Node.js, local loopback HTTP, administrator and gateway role secrets, local JSON persistence.
- Ed25519 signed ordinary JWTs with SPIFFE-shaped instance IDs, explicitly not conforming SVIDs or live SPIRE.
- Administrator-assigned profiles and per-operation policy, with short-lived flow/context-scoped activity grants.
- Real online authorization and in-process application queue ordering; illustrative DSCP intent, not packet QoS.
- Synthetic recipe, travel, health and security agents; negative scenarios for escalation, scope mismatch and revocation.
- Twenty automated tests and public-HTTP CLI demo evidence; browser verification of the dashboard.

The diagram and external requirements were treated as source material. No Jira or SharePoint write, source publication, video upload, or recording was performed in this implementation session.
