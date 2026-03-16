# Operations Guide

This guide focuses on safe operation of `fortipot` in a blue-team workflow.

## Recommended Rollout

1. Start in `detect_only`.
2. Validate packet visibility and scoring behavior.
3. Add allowlists for known-critical assets.
4. Confirm local/private CIDRs are correct.
5. Move to `approval_required`.
6. Lab-validate quarantine and release workflows.
7. Only then enable automatic enforcement.

## Modes

## `detect_only`

- recommended for first deployments
- records events
- records skipped actions where applicable
- does not change network state

## `approval_required`

- creates proposed actions
- requires explicit approval flow
- useful before enabling auto-enforcement

## `fortigate_quarantine`

- intended for local/private endpoints
- works best with MAC and inventory context
- should be used only after lab validation

## `fortigate_block_public`

- intended for public/non-private sources
- uses a block action path instead of VLAN quarantine semantics

## Safety Rails

`fortipot` includes the following guardrails:

- allowlists by IP, CIDR, MAC, and hostname
- exemption tags
- confidence threshold for auto-action
- cooldown by source
- max automatic actions per minute
- optional MAC requirement for local quarantine
- dry-run mode
- release support

## Reviewing Activity

CLI:

```powershell
fortipot events list --config config.yaml
fortipot actions list --config config.yaml
```

API:

```bash
curl http://127.0.0.1:8080/events
curl http://127.0.0.1:8080/actions
```

## Response Workflow

When an event is generated:

1. Review source classification.
2. Review matched behaviors and score.
3. Review endpoint identity enrichment if local/private.
4. Confirm the host is not allowlisted or operationally sensitive.
5. Decide whether to approve, quarantine, block, or release.

## Release Workflow

CLI:

```powershell
fortipot quarantine release --ip 10.0.0.25 --config config.yaml
fortipot quarantine release --mac aa:bb:cc:dd:ee:ff --config config.yaml
```

API:

```bash
curl -X POST http://127.0.0.1:8080/actions/release \
  -H "Content-Type: application/json" \
  -d '{"ip":"10.0.0.25"}'
```

## Operational Caveats

- Local quarantine quality depends on MAC and switch/VLAN context.
- Public IP blocking may affect shared infrastructure if used carelessly.
- Approval and release actions should be auditable and reviewed.
