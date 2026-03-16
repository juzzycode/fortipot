# FortiGate Integration

The FortiGate integration in `fortipot` is intentionally conservative and abstracted.

## Design Intent

The FortiGate layer should:

- keep vendor-specific details out of the detector
- support dry-run testing
- stay easy to mock in unit tests
- isolate environment-specific API assumptions

## Current Client Capabilities

The client exposes:

- `quarantine_endpoint(...)`
- `release_endpoint(...)`
- `block_public_ip(...)`
- `healthcheck(...)`

Configured options include:

- base URL
- token environment variable name
- optional VDOM
- TLS verification toggle
- request timeout
- retry count

## Quarantine Model

For local/private endpoints, the preferred workflow is:

1. identify the source as local/private
2. resolve a MAC address if possible
3. quarantine using the FortiGate-backed path
4. record the action in SQLite
5. support later release

Why MAC matters:

- MAC-based isolation generally aligns better with local endpoint containment than raw IP-only handling
- DHCP churn can make IP-only logic less reliable

## Public IP Block Model

For public sources:

- do not use VLAN quarantine semantics
- map suspicious activity to the public block action path
- record block and release events clearly

## Dry-Run Support

When `app.dry_run` is `true`, the client returns structured dry-run payloads and avoids changing network state.

This is the recommended setting for:

- initial testing
- CI-style validation
- documentation walkthroughs
- API contract checks

## Lab Validation Checklist

Before production use, validate:

1. FortiGate API token scope and permissions
2. VDOM handling
3. certificate verification behavior
4. quarantine object semantics in your firmware version
5. public block semantics and rollback path
6. release behavior for both local and public actions
7. logging and observability around API failures

## Important Caveat

The current API paths are placeholder-friendly wrappers. They are intentionally isolated in [`fortipot/enforcer/fortigate.py`](/Users/Juzzy/Documents/GitHub/fortipot/fortipot/enforcer/fortigate.py) so you can adapt them to your environment without rewriting the rest of the product.
