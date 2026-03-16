# Architecture

`fortipot` is structured as a defensive detection-and-enforcement service with clean module boundaries so the risky parts stay isolated and testable.

## High-Level Flow

1. Passive collectors observe network activity or local caches.
2. Packets are normalized into `PacketEvent` objects.
3. The detector updates rolling per-source state.
4. Indicators and matched behaviors are derived.
5. A score and confidence value are calculated.
6. The source is classified as local/private, public, allowlisted, or unknown.
7. A recommended action is generated.
8. The decision is stored in SQLite.
9. Depending on mode and safety checks, an action is skipped, queued, or executed.
10. Actions and releases are stored in SQLite for auditability.

## Package Layout

- `fortipot/cli.py`: Typer CLI entrypoints
- `fortipot/main.py`: runtime assembly, decision flow, approval/release hooks
- `fortipot/config.py`: YAML loading and schema validation
- `fortipot/models.py`: shared typed models and enums
- `fortipot/logging_utils.py`: structured logging configuration
- `fortipot/collector/`: passive data ingestion helpers
- `fortipot/detector/`: rolling window state, indicators, and scoring
- `fortipot/resolver/`: passive endpoint identity enrichment
- `fortipot/enforcer/`: quarantine and public-block abstractions
- `fortipot/api/`: FastAPI app and route handlers
- `fortipot/storage/`: SQLite schema and persistence helpers
- `fortipot/utils/`: focused helpers for IPs, MACs, and time

## Key Design Choices

## Passive by Default

The collector and resolver intentionally avoid active probing. Resolution relies on local caches and inventory data where available.

## Safety First

Detection does not directly imply enforcement. `fortipot` uses:

- detect-only mode
- approval-required mode
- cooldown checks
- action rate limits
- confidence gates
- MAC requirements for local quarantine

## Adapter-Friendly Enforcement

FortiGate-specific assumptions are isolated in the client wrapper. This keeps API path variance out of detection logic.

## Auditable Persistence

Events and actions are written to SQLite using explicit helper functions so the service remains inspectable and easy to test locally.

## Runtime Components

`Runtime` in [`fortipot/main.py`](/Users/Juzzy/Documents/GitHub/fortipot/fortipot/main.py) wires together:

- `DetectionEngine`
- `EndpointResolver`
- `PacketCaptureListener`
- `QuarantineEnforcer`
- `PublicBlockEnforcer`
- `ActionGuard`

## Current MVP Boundaries

- live capture is implemented with `scapy`, but it is still only lightly hardened and focused on common IPv4 LAN traffic
- approval replay is still a placeholder workflow
- FortiGate endpoints are conservative wrappers that require lab validation
