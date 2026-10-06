# Shared team architecture

Open `pmbu-agent-architecture.drawio` in diagrams.net / draw.io. It contains two editable pages with individual nodes and attached connectors. PNG exports are ready for Jira, chat or a slide; SVG exports preserve vector quality. `tools/build_architecture.py` generates the initial source layouts; after teammates edit the draw.io file, use that file as the shared master instead of rerunning the generator over their edits.

## Views

1. **Team architecture**: local workload activities, temporary identity and enterprise policy, hosted connectivity authorization, access/edge/enterprise adapters, feedback, and suggested four-person ownership.
2. **Cellular lab integration**: the supplied topology with a proposed identity-service and connectivity-adapter overlay. Host addresses and N2/N3/N4/N6/N7/N11 labels are retained from the screenshot. Access has not yet been provisioned or tested in this session.

Teal identifies working local prototype components. Amber identifies planned deployment or integration. Blue identifies supplied lab infrastructure. Solid purple lines show policy/control, blue shows traffic or routing, and green dashed lines show monitoring feedback. Connections are schematic; crossing lines without a dot are not joined. Arrows show the principal logical direction, not the complete bidirectional protocol exchange.

## Supplied lab inventory

| Screenshot component | Supplied host address | How it appears in the design |
|---|---|---|
| lattice + Agent1 / Agent2 | 10.8.102.55 | Endpoint lab host; proposed identity clients and trusted flow binding |
| AMF / SMF / PCF / UPF | 10.8.102.208 | Cellular core; policy and user-plane path |
| AI Cloud | 10.8.102.52 | Candidate host for connectivity decision service and PCF adapter |
| ISE | 10.8.95.13 | Existing RADIUS-related lab integration, separate from workload identity issuance |
| CC / UDR | Not supplied | Existing component and unlabeled association retained |
| Router / Internet | Not supplied | Existing routing path; QoS support must be confirmed |

These are host addresses copied from the screenshot. They are not confirmed subscriber UE addresses, workload identities, or individual NF service endpoints. The precise role of lattice and the CC/UDR-to-core interface remain unverified.

## Suggested implementation sequence

1. Keep the identity prototype local while the teammate arranges access; agree on API schemas using `docs/API.md`.
2. Confirm connectivity to the four supplied hosts and identify the PCF API actually available to the AI Cloud host. Obtain credentials through the team's approved channel.
3. Identify a trustworthy association between agent workload, network flow, subscriber and PDU session. Do not use the host IP alone to identify an agent.
4. Deploy agent clients and a connectivity adapter where the lab owner approves. The current service binds to loopback; remote deployment needs authenticated TLS and explicit network configuration.
5. Implement PCF policy requests using the supported lab interface. Confirm whether direct authorized PCF access or an AF/NEF route is required; the diagram does not claim a verified API or N5 implementation.
6. Confirm the supported QoS profiles and traffic filters, then demonstrate differentiation at a measurable bottleneck. Keep background model updates and alerts as separate activities from the same agent instance.
7. Test policy change, expiry and revocation across the actual enforcement layer. Capture applied-policy and traffic evidence for the recording.

The PCF → SMF → UPF chain is the proposed cellular integration path. The SMF interfaces N7 (PCF–SMF), N11 (AMF–SMF) and N4 (SMF–UPF) are documented in [Cisco's SMF interface reference](https://www.cisco.com/c/en/us/td/docs/wireless/ucc/smf/2026-01/config-admin/ucc-5g-smf-configuration-and-administration-guide--release-2026-01/m_smf_interfaces_3gpp_spec_compliance.html). The actual lab product/version and policy APIs must be confirmed before implementation.

## Decisions for the team

- Who owns each suggested workstream, and where should the identity service be deployed?
- Is enterprise policy/approval backed by an actual Duo integration for this HF, or kept as the local model?
- Is SPIRE available in the lab, or does the local issuer remain the demo identity source?
- Which PCF API, traffic filter fields, subscriber/session association and QoS profiles are supported?
- Does the demo measure access-network QoS, UPF shaping, router queues, or application scheduling? Label the evidence accordingly.

The architecture does not equate DSCP with a cellular 5QI or claim that a host route provisions QoS. Live enterprise identity, attestation, flow binding and network enforcement remain planned integrations.
