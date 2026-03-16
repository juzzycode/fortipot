# Detection And Scoring

`fortipot` uses a rolling behavioral model rather than firing on one packet.

## Processing Pipeline

1. Normalize observed traffic into `PacketEvent`.
2. Maintain rolling state per source IP.
3. Derive indicators from the current window.
4. Translate indicators into named suspicious behaviors.
5. Calculate a score and confidence value.
6. Classify the source.
7. Produce a recommended action.

## Normalized Event Types

Current normalized event kinds:

- TCP
- UDP
- ICMP
- ARP

Normalized fields can include:

- `src_ip`
- `dst_ip`
- `src_mac`
- `dst_port`
- `tcp_flags`
- `arp_target_ip`
- `timestamp`

## Rolling State

State is maintained per source using a rolling time window. This lets the detector reason about:

- unique destination IP diversity
- unique destination port diversity
- ARP target diversity
- ICMP sweep diversity
- service fan-out toward sensitive ports

## Indicators

The current detector derives:

- `unique_hosts`
- `unique_ports`
- `arp_targets`
- `icmp_targets`
- `syn_ports`
- `service_fanout_<port>`

## Matched Behaviors

The current MVP maps indicators to behaviors such as:

- `tcp_syn_scan`
- `host_fanout`
- `arp_sweep`
- `icmp_sweep`
- `service_fanout_22`
- `service_fanout_445`
- `service_fanout_3389`
- `service_fanout_5985`

## Score Model

The score is composed from a few capped signal buckets:

- unique ports
- unique hosts
- ARP target count
- ICMP target count
- matched behavior count

Confidence is derived from score relative to the isolation threshold.

## Action Mapping

Current action recommendations:

- below alert threshold: `log`
- at or above alert threshold: `alert`
- at or above isolate threshold: `quarantine`

Then policy adjusts that action:

- public sources map alert-or-higher to `block_public_ip`
- allowlisted or exempt sources map to `none`

## Tuning Guidance

- Raise thresholds in noisy east-west environments.
- Lower thresholds in tightly controlled small networks.
- Treat sensitive service fan-out carefully around management systems.
- Use `detect_only` first and review event history before enabling automation.
