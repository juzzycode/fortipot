# Configuration Reference

`fortipot` uses YAML configuration with light environment-variable overrides. The canonical example is in `config.example.yaml`.

## Top-Level Sections

- `app`
- `capture`
- `detection`
- `classification`
- `allowlists`
- `safety`
- `fortigate`
- `storage`
- `alerts`

## app

Controls global runtime behavior.

- `name`: application name used for identification
- `mode`: one of `detect_only`, `approval_required`, `fortigate_quarantine`, `fortigate_block_public`
- `dry_run`: when `true`, enforcement clients stay non-destructive
- `log_level`: standard log level such as `INFO` or `DEBUG`

Example:

```yaml
app:
  name: fortipot
  mode: detect_only
  dry_run: true
  log_level: INFO
```

## capture

Controls passive packet collection.

- `interface`: interface to observe
- `promiscuous`: enable promiscuous mode if supported and appropriate
- `bpf_filter`: optional BPF filter string
- `use_pcap`: toggle packet-capture path usage

Example:

```yaml
capture:
  interface: eth0
  promiscuous: true
  bpf_filter: ""
  use_pcap: true
```

## detection

Controls the rolling scoring model and thresholds.

- `window_seconds`: size of the rolling analysis window
- `alert_score`: score where behavior becomes alert-worthy
- `isolate_score`: score where enforcement may be considered
- `syn_scan_ports_threshold`: unique SYN destination ports threshold
- `host_fanout_threshold`: unique destination host threshold
- `arp_sweep_threshold`: ARP target diversity threshold
- `icmp_sweep_threshold`: ICMP target diversity threshold
- `service_fanout_ports`: ports treated as sensitive lateral-movement targets

Example:

```yaml
detection:
  window_seconds: 15
  alert_score: 25
  isolate_score: 50
  syn_scan_ports_threshold: 10
  host_fanout_threshold: 8
  arp_sweep_threshold: 12
  icmp_sweep_threshold: 10
  service_fanout_ports:
    - 22
    - 445
    - 3389
    - 5985
```

## classification

Controls how sources are classified as local/private vs public.

- `local_cidrs`: user-defined CIDRs to treat as local
- `treat_link_local_as_local`: treat link-local space as local/private

Example:

```yaml
classification:
  local_cidrs:
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
  treat_link_local_as_local: true
```

## allowlists

Controls assets that should not be automatically acted on.

- `cidrs`: entire networks to exempt from automated handling
- `ips`: individual IP addresses to exempt
- `macs`: specific MAC addresses to exempt
- `hostnames`: known hostnames to exempt
- `exempt_tags`: inventory tags for critical assets and infrastructure

Use allowlists sparingly and review them regularly.

Example:

```yaml
allowlists:
  cidrs:
    - 10.20.30.0/24
  ips:
    - 10.0.0.10
  macs:
    - aa:bb:cc:dd:ee:ff
  hostnames:
    - dc01
  exempt_tags:
    - domain-controller
    - backup-infrastructure
```

## safety

These settings are important. They reduce the chance of noisy or unsafe auto-enforcement.

- `auto_release_minutes`: release window for temporary enforcement
- `cooldown_minutes`: minimum time between automatic actions for the same source
- `max_auto_actions_per_minute`: rate limit for automated actions
- `require_mac_for_local_quarantine`: require MAC context before local quarantine
- `min_confidence_for_isolation`: minimum confidence score before automated enforcement

Example:

```yaml
safety:
  auto_release_minutes: 60
  cooldown_minutes: 30
  max_auto_actions_per_minute: 5
  require_mac_for_local_quarantine: true
  min_confidence_for_isolation: 0.8
```

## fortigate

Controls FortiGate client behavior.

- `base_url`: FortiGate base URL
- `token_env`: environment variable name that stores the API token
- `vdom`: optional VDOM
- `verify_tls`: verify TLS certificates
- `request_timeout_seconds`: HTTP timeout
- `retries`: retry count for client operations

Example:

```yaml
fortigate:
  base_url: https://192.168.1.1
  token_env: FORTIPOT_FGT_TOKEN
  vdom: root
  verify_tls: true
  request_timeout_seconds: 10
  retries: 2
```

## storage

Controls SQLite persistence.

- `sqlite_path`: path to the local database file

Example:

```yaml
storage:
  sqlite_path: ./fortipot.db
```

## alerts

Controls outbound alerting hooks.

- `stdout`: emit alerts to stdout/logs
- `webhook_url`: optional webhook destination

Example:

```yaml
alerts:
  stdout: true
  webhook_url: ""
```

## Environment Variable Overrides

Current direct overrides include:

- `FORTIPOT_CONFIG`
- `FORTIPOT_MODE`
- `FORTIPOT_DRY_RUN`
- `FORTIPOT_LOG_LEVEL`
- `FORTIPOT_SQLITE_PATH`
- `FORTIPOT_FGT_TOKEN`

## Recommended Operating Pattern

1. Tune `detection` thresholds for your LAN.
2. Define `classification.local_cidrs` precisely.
3. Populate `allowlists` for critical systems.
4. Start with `detect_only`.
5. Move to `approval_required` before enabling automatic enforcement.
