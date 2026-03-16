# fortipot

`fortipot` is a defensive network tripwire for modern LANs. It is inspired by portsentry, but uses passive packet observation, rolling behavior scoring, and safety-first enforcement workflows designed for FortiGate-backed environments.

This project is for blue-team defensive use only. It does not include exploit logic, active scanning, credential attacks, or offensive automation.

## What It Does

- Detects suspicious reconnaissance and lateral movement patterns from passive observations
- Scores behavior over rolling time windows instead of firing on a single packet
- Classifies sources as local/private vs public/non-private
- Resolves local endpoints with passive data such as ARP, DHCP leases, and inventory caches
- Supports detect-only, approval-required, FortiGate quarantine, and public-IP block workflows
- Can expose optional bait ports with fake service banners for deception and tripwire value
- Records audit events and enforcement history in SQLite
- Exposes a local CLI and FastAPI service for operations and review

## Supported Modes

- `detect_only`
- `approval_required`
- `fortigate_quarantine`
- `fortigate_block_public`

## Architecture Overview

- `collector/`: passive packet and cache ingestion
- `detector/`: normalized events, rolling windows, scoring, action recommendation
- `resolver/`: endpoint identity enrichment for local/private sources
- `enforcer/`: abstract and FortiGate-backed enforcement workflows
- `storage/`: SQLite persistence for events, actions, approvals, and releases
- `api/`: FastAPI endpoints for health, events, actions, approvals, and releases
- `cli.py`: operational commands for running, config validation, review, and simulation

## Install

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".[dev]"
```

On Linux or macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".[dev]"
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".[dev]"
```

## Quick Start

```bash
fortipot check-config --config config.example.yaml
fortipot run --config config.example.yaml
fortipot api --config config.example.yaml --host 127.0.0.1 --port 8080
```

## Docs

- [`docs/README.md`](/Users/Juzzy/Documents/GitHub/fortipot/docs/README.md)
- [`docs/quickstart.md`](/Users/Juzzy/Documents/GitHub/fortipot/docs/quickstart.md)
- [`docs/configuration.md`](/Users/Juzzy/Documents/GitHub/fortipot/docs/configuration.md)
- [`docs/api.md`](/Users/Juzzy/Documents/GitHub/fortipot/docs/api.md)
- [`docs/architecture.md`](/Users/Juzzy/Documents/GitHub/fortipot/docs/architecture.md)
- [`docs/detection-and-scoring.md`](/Users/Juzzy/Documents/GitHub/fortipot/docs/detection-and-scoring.md)
- [`docs/operations.md`](/Users/Juzzy/Documents/GitHub/fortipot/docs/operations.md)
- [`docs/fortigate.md`](/Users/Juzzy/Documents/GitHub/fortipot/docs/fortigate.md)
- [`docs/development.md`](/Users/Juzzy/Documents/GitHub/fortipot/docs/development.md)

## Config Example

The repository includes `config.example.yaml` and `.env.example`. YAML is the primary config source, with environment variable overrides for common runtime settings like `FORTIPOT_MODE`, `FORTIPOT_DRY_RUN`, and `FORTIPOT_SQLITE_PATH`.

## CLI

- `fortipot run`
- `fortipot check-config`
- `fortipot health`
- `fortipot explain-rules`
- `fortipot events list`
- `fortipot actions list`
- `fortipot quarantine release --ip ...`
- `fortipot quarantine release --mac ...`
- `fortipot simulate --scenario syn_scan`
- `fortipot version`

`fortipot version` prints the base release plus a build number when git history is available, for example `0.1.0.12345`.

## API

- `GET /health`
- `GET /rules`
- `GET /events`
- `GET /actions`
- `POST /actions/approve`
- `POST /actions/release`
- `GET /config/redacted`

Example:

```bash
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/rules
curl http://127.0.0.1:8080/events
curl -X POST http://127.0.0.1:8080/actions/approve -H "Content-Type: application/json" -d '{"action_id":1}'
curl -X POST http://127.0.0.1:8080/actions/release -H "Content-Type: application/json" -d '{"ip":"10.0.0.25"}'
```

## Detection Design

The detector normalizes passive observations, tracks them in per-source rolling windows, derives behavioral indicators, calculates a score, applies classification and allowlists, and then recommends log, alert, quarantine, or public block behavior. The current MVP includes coverage for TCP SYN fan-out, host fan-out, ICMP sweep patterns, ARP sweep diversity, and suspicious service fan-out on ports such as 22, 445, 3389, and 5985.

Optional bait services can also expose fake HTTP, SSH, DNS, and Samba responses. Touching configured bait ports adds a dedicated `bait_port_touch` behavior to the detector.

## Persistence

SQLite is used for local persistence of:

- event records
- enforcement attempts
- approval queue records
- release actions

This keeps the MVP auditable and easy to test locally.

## Safety Notes

- Public IPs should be blocked rather than VLAN-quarantined.
- Local endpoint quarantine works best when your environment supports endpoint isolation workflows.
- Dry-run mode keeps enforcement testable without changing network state.
- Automated enforcement is gated by minimum confidence, cooldowns, MAC requirements for local quarantine, and per-minute action limits.
- Exact FortiGate API behavior varies by environment and should be validated in a lab before production use.
- On Linux, promiscuous capture permissions come from OS capabilities or tools like `dumpcap`, not from the Python virtual environment.

## Limitations

- Live packet capture is implemented for IPv4 TCP, UDP, ICMP, and ARP, but it is not yet hardened for every link type or protocol variant.
- Endpoint resolution is passive only and intentionally avoids active probing.
- Approval execution currently records the approval intent and leaves replay semantics as a documented next step.
- FortiGate API paths are isolated behind a client abstraction, but exact firmware behavior still requires lab validation.

## FortiGate Notes

- MAC-based local quarantine is preferred when available.
- Public IP handling uses a separate block path instead of VLAN quarantine semantics.
- The client supports dry-run mode, token-based auth, optional VDOM, TLS verification, and a health check wrapper.
- Environment-specific FortiGate API behavior is intentionally isolated in the client layer rather than hardcoded in detection logic.

## Roadmap

- Phase 1: scaffold, config, storage, CLI, API, docs
- Phase 2: passive normalization, rolling scoring, classification, tests
- Phase 3: FortiGate client abstraction, approval flow, release flow
- Phase 4: API polish, simulations, expanded tests, hardening
