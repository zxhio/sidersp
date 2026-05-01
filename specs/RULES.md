# Rules

This document defines the rule contract, matching semantics, validation rules, and dataplane action encoding.

## Rule Set

Rules are stored as a list under the top-level `rules` field:

```yaml
rules:
  - name: http_tcp_reset
    enabled: true
    priority: 100
    match:
      protocol: tcp
      vlans: [100, 200]
      src_prefixes: ["10.0.0.0/8"]
      dst_prefixes: ["192.168.1.0/24"]
      src_ports: [12345, 23456]
      dst_ports: [80, 8080]
      tcp_flags:
        syn: true
    response:
      action: tcp_reset
```

`id` may be omitted in input YAML or API create requests. The control plane
assigns a unique positive ID, keeps provided positive IDs unchanged, and writes
the finalized IDs back when the rule set is persisted.

## Rule Fields

| Field | Required | Default | Semantics |
|-------|----------|---------|-----------|
| `id` | input: no, persisted: yes | auto-assigned | Internal unique non-zero rule ID used by CRUD, stats, and event attribution |
| `name` | yes | none | Non-empty display and audit name |
| `enabled` | no | `false` | Disabled rules remain in config but are not loaded into the dataplane |
| `priority` | no | `0` | Lower number means higher priority; must be `>= 0` |
| `match` | no | empty | Positive match conditions |
| `response` | yes | none | Action executed after a match |

## Match Conditions

All match fields are positive conditions. Negative conditions are not supported.

| Field | Values | Semantics |
|-------|--------|-----------|
| `protocol` | `tcp`, `udp`, `icmp`, `arp` | Optional protocol condition |
| `vlans` | `0..4095` | Optional VLAN ID list |
| `src_prefixes` | IPv4 CIDR list | Optional source IPv4 prefix list |
| `dst_prefixes` | IPv4 CIDR list | Optional destination IPv4 prefix list |
| `src_ports` | `1..65535` | Optional TCP/UDP source port list |
| `dst_ports` | `1..65535` | Optional TCP/UDP destination port list |
| `tcp_flags` | `syn`, `ack`, `rst`, `fin`, `psh` | Optional TCP flag requirements; only `true` is allowed |
| `icmp.type` | `echo_request`, `echo_reply` | Optional ICMP type condition |
| `arp.operation` | `request`, `reply` | Optional ARP operation condition |

Invalid negative condition:

```yaml
tcp_flags:
  syn: true
  ack: false
```

The rule model does not include a `features` field.

## Response

```yaml
response:
  action: tcp_reset
  params: {}
```

| Field | Required | Semantics |
|-------|----------|-----------|
| `action` | yes | Snake-case action name |
| `params` | no | Action-specific response parameters; schema depends on `action` |

`response.params` is not encoded into BPF `rule_meta`. The control plane
validates it per action and the response consumer uses it only for actions that
require user-space response parameters.

Parameter schema:

| Action | `response.params` |
|--------|-------------------|
| `none` | forbidden |
| `alert` | forbidden |
| `tcp_reset` | forbidden |
| `icmp_echo_reply` | forbidden |
| `arp_reply` | optional `hardware_addr` string containing one Ethernet MAC address; optional `sender_ipv4` string containing one IPv4 address |
| `tcp_syn_ack` | optional `tcp_seq` integer in `0..4294967295`; omitted defaults to `1` |
| `icmp_port_unreachable` | forbidden |
| `icmp_host_unreachable` | forbidden |
| `icmp_admin_prohibited` | forbidden |
| `udp_echo_reply` | forbidden |
| `dns_refused` | optional `rcode` string: `refused`, `nxdomain`, or `servfail`; omitted defaults to `refused` |
| `dns_sinkhole` | required `family` string: `ipv4`, `ipv6`, or `dual`; `answers_v4` is required for `ipv4` and `dual`; `answers_v6` is required for `ipv6` and `dual`; optional `ttl` integer in `0..2147483647`, omitted defaults to `60` |

Execution path is not exposed as a rule field. The control plane validates `response.action`; dataplane compilation encodes it into the numeric action code. Dataplane and response modules own the configured execution path for each action. For kernel TX actions such as `tcp_reset` and `icmp_port_unreachable`, local runtime config selects same-interface `XDP_TX` or egress-interface redirect for all rules.

## Actions

| Action | Code | Execution Path | Semantics |
|--------|------|----------------|-----------|
| `none` | `0` | dataplane | Match silently; final host-stack disposition follows runtime `dataplane.ingress_verdict` |
| `alert` | `1` | dataplane | Emit an observation event; final host-stack disposition follows runtime `dataplane.ingress_verdict` |
| `tcp_reset` | `2` | dataplane kernel TX | Build TCP RST in BPF and send by configured same-interface or egress-interface TX mode |
| `icmp_echo_reply` | `3` | XSK RX + user-space TX | Redirect original packet to XSK; the dataplane-owned XSK runtime dispatches it to the response consumer, which builds ICMP echo reply and transmits through same-interface XSK TX or configured shared TX egress |
| `arp_reply` | `4` | XSK RX + user-space TX | Redirect original packet to XSK; the dataplane-owned XSK runtime dispatches it to the response consumer, which builds ARP reply and transmits through same-interface XSK TX or configured shared TX egress, with optional per-rule sender MAC / sender IPv4 override |
| `tcp_syn_ack` | `5` | XSK RX + user-space TX | Redirect original packet to XSK; the dataplane-owned XSK runtime dispatches it to the response consumer, which builds TCP SYN-ACK, with optional per-rule `response.params.tcp_seq` override |
| `icmp_port_unreachable` | `6` | dataplane kernel TX | Build ICMP destination-unreachable / port-unreachable in BPF and send by configured same-interface or egress-interface TX mode |
| `udp_echo_reply` | `7` | XSK RX + user-space TX | Redirect original packet to XSK; the dataplane-owned XSK runtime dispatches it to the response consumer, which swaps the UDP tuple and echoes the original payload |
| `dns_refused` | `8` | XSK RX + user-space TX | Redirect original packet to XSK; the dataplane-owned XSK runtime dispatches it to the response consumer, which returns a DNS refusal-style response for a compatible UDP DNS query, with `rcode` chosen from `refused`, `nxdomain`, or `servfail` |
| `icmp_host_unreachable` | `9` | dataplane kernel TX | Build ICMP destination-unreachable / host-unreachable in BPF and send by configured same-interface or egress-interface TX mode |
| `icmp_admin_prohibited` | `10` | dataplane kernel TX | Build ICMP destination-unreachable / administratively-prohibited in BPF and send by configured same-interface or egress-interface TX mode |
| `dns_sinkhole` | `11` | XSK RX + user-space TX | Redirect original packet to XSK; the dataplane-owned XSK runtime dispatches it to the response consumer, which returns a DNS `NOERROR` response with A and/or AAAA answers selected from `response.params` by query type |

External rules must not expose implementation details such as `xdp`, `xsk`, or `user_space` as fields.
`dataplane.ingress_verdict` is a runtime dataplane setting, not a per-rule field.

## Action Compatibility

The control plane rejects actions whose match conditions do not select the
packet type required to construct the response:

| Action | Required match conditions |
|--------|---------------------------|
| `icmp_echo_reply` | `protocol: icmp` and `icmp.type: echo_request` |
| `arp_reply` | `protocol: arp` and `arp.operation: request` |
| `tcp_syn_ack` | `protocol: tcp` and `tcp_flags.syn: true` |
| `icmp_port_unreachable` | `protocol: udp` |
| `icmp_host_unreachable` | `protocol: udp` |
| `icmp_admin_prohibited` | `protocol: udp` |
| `udp_echo_reply` | `protocol: udp` |
| `dns_refused` | `protocol: udp` |
| `dns_sinkhole` | `protocol: udp` |

`dns_refused` and `dns_sinkhole` v1 support IPv4 UDP DNS queries only. Rules
should usually also limit `dst_ports` to `53`, but the control plane does not
hard-require that port in v1.

## Match Semantics

- A rule matches only when all configured positive conditions match.
- Empty or omitted match fields are wildcards for that field.
- If multiple rules match, the first compiled rule wins.
- Compiled rule order is `(priority ASC, id ASC)`.
- Disabled rules are excluded before dataplane compilation.

## Control Plane Validation

The control plane must:

- Assign IDs to rules whose input `id` is missing or `0`
- Reject duplicate rule IDs after assignment
- Reject negative `id`, empty `name`, missing `response.action`, or negative `priority`
- Normalize action and protocol names to lower case
- Validate protocol, action, ICMP type, and ARP operation values
- Validate `response.params` by action schema and reject unknown keys
- Reject XSK TX actions without compatible match conditions
- Validate VLAN, port, and IPv4 CIDR ranges
- Reject negative TCP flag conditions
- Filter `enabled=false` rules before dataplane loading
- Send only enabled rules to the dataplane sync path

## Dataplane Compilation

The dataplane sync path compiles enabled rules into dataplane maps.

Compiled rule order is `(priority ASC, id ASC)`.

Indexed match values:

- VLAN IDs
- Source ports
- Destination ports
- Source IPv4 prefixes
- Destination IPv4 prefixes

Positive semantic conditions are encoded into `required_mask`.

Kernel-side `rule_meta` contains only active compiled rule data:

```text
rule_id
required_mask
action
flags
```

The following rule fields are not stored in `rule_meta`:

- `enabled`
- `priority`
- `name`
- `response.params`

Final dataplane match check:

```text
(pkt_conds & required_mask) == required_mask
```

## Related Contracts

- Module boundaries: `MODULES.md`
- Event structure: `EVENTS.md`
- Response execution: `RESPONSES.md`
