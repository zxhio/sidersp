# Systemd Deployment

This document describes the single-host Linux deployment path for SideSP. It
uses a native systemd service running as root and keeps deployment logic outside
the runtime modules.

## Layout

| Asset | Path |
|-------|------|
| Binary | `/usr/local/bin/sidersp` |
| Config | `/etc/sidersp/config.yaml` |
| Rules | `/etc/sidersp/configs/rules.example.yaml` |
| Unit | `/etc/systemd/system/sidersp.service` |
| Logs | `/var/log/sidersp/sidersp.log`, `/var/log/sidersp/sidersp.stats.log`, `/var/log/sidersp/sidersp.event.log` |

## Requirements

- Linux with systemd.
- Root privileges. SideSP loads BPF programs, attaches XDP, and may open AF_XDP
  sockets.
- A mirrored-traffic interface dedicated to the dataplane.
- A binary built before installation. The unit does not build the service.

## Build A Release Package

Build a tarball for distribution:

```bash
make package VERSION=0.1.0
```

The output is written to `dist/sidersp-<version>-linux-amd64.tar.gz`.
Build release packages on a Linux host with the BPF build dependencies
available.

Package contents:

```text
build/sidersp
configs/config.example.yaml
configs/rules.example.yaml
deploy/systemd/sidersp.service
scripts/install-systemd.sh
scripts/uninstall-systemd.sh
docs/deployment.md
README.md
README.zh-CN.md
RELEASE
```

The built-in Web console is embedded into `build/sidersp`; there is no separate
web directory to deploy.

Copy the tarball to the target host, extract it, and run the installer from the
extracted package directory:

```bash
tar -xzf sidersp-0.1.0-linux-amd64.tar.gz
cd sidersp-0.1.0-linux-amd64
sudo scripts/install-systemd.sh
```

Review `/etc/sidersp/config.yaml`, then start the service explicitly:

```bash
sudo systemctl start sidersp
```

If this host should start SideSP on boot:

```bash
sudo systemctl enable sidersp
```

## Install From Source Checkout

For local development or direct installation from a checkout, build the Linux
binary first:

```bash
make build-all
```

Preview the install:

```bash
scripts/install-systemd.sh --dry-run
```

Install without starting:

```bash
sudo scripts/install-systemd.sh
```

Install, enable, and start:

```bash
sudo scripts/install-systemd.sh --enable --start
```

When `--start` is used during an upgrade, the installer restarts `sidersp` if
it is already running so the new binary takes effect immediately.

The installer copies the example config and rules with their default values.
Existing `/etc/sidersp/config.yaml` and
`/etc/sidersp/configs/rules.example.yaml` are preserved by default. Pass
`--force` to overwrite them from the repository examples.

After installation, edit `/etc/sidersp/config.yaml` if the mirrored interface
or XDP attach mode differs from the defaults.

## XDP Attach Mode

Use `dataplane.attach_mode: generic` for initial validation or when the
NIC/driver does not support native XDP. Generic mode is slower but broadly
available.

Use `dataplane.attach_mode: driver` for normal production testing on a NIC with
native XDP support.

Use `dataplane.attach_mode: offload` only when the NIC supports hardware
offload and the deployment has been validated for that driver and firmware.

SideSP enables promiscuous mode on the dataplane interface during startup. This
is required for mirrored traffic where frames are not addressed to the interface
MAC.

Verify runtime interface flags with:

```bash
ip link show <interface>
```

## Response AF_XDP Notes

The default example config keeps `response.runtime.enabled: false`. If AF_XDP
response workers are enabled, verify queue IDs, NIC support, UMEM sizing, and
source hardware address settings before starting the service. AF_XDP setup
failures will fail service startup and systemd will restart according to the
unit policy.

## Shared Response TX Egress

For a pure switch mirror/SPAN destination port, do not rely on same-port
transmission for active responses. Set `egress.interface` to send
supported responses from a separate interface that participates in normal
switching or routing:

```yaml
egress:
  interface: eth1
  vlan_mode: access
  failure_verdict: drop
```

Use `vlan_mode: access` when the response interface is an access port. Use
`vlan_mode: preserve` when the response interface is a trunk that should carry
the original single 802.1Q tag.

Current shared-TX behavior:

- `tcp_reset` uses BPF/kernel redirect TX through the configured egress
  interface.
- `icmp_echo_reply` keeps ingress RX on AF_XDP, then transmits the reply through
  the configured egress interface in user space.
- `arp_reply` keeps ingress RX on AF_XDP, then transmits the reply frame through
  the configured egress interface in user space.

When `egress_interface` is non-empty, ensure the host has a valid route for the
response destination through the configured egress interface.

## Operate

Check service state:

```bash
systemctl status sidersp
```

View logs:

```bash
tail -n 100 /var/log/sidersp/sidersp.log
tail -f /var/log/sidersp/sidersp.log
tail -f /var/log/sidersp/sidersp.stats.log
tail -f /var/log/sidersp/sidersp.event.log
```

Query the local console API:

```bash
curl http://127.0.0.1:8080/api/v1/status
```

Open the built-in Web console:

```text
http://127.0.0.1:8080/
```

Check the current log level:

```bash
curl http://127.0.0.1:8080/api/v1/logging/level
```

Check all runtime log levels:

```bash
curl http://127.0.0.1:8080/api/v1/logging/levels
```

Change the app-channel runtime log level:

```bash
curl -X PUT http://127.0.0.1:8080/api/v1/logging/level \
  -H 'Content-Type: application/json' \
  -d '{"level":"debug"}'
```

Change all runtime log levels:

```bash
curl -X PUT http://127.0.0.1:8080/api/v1/logging/levels \
  -H 'Content-Type: application/json' \
  -d '{"app":"debug","stats":"info","event":"warn"}'
```

Runtime log-level changes are not written back to `/etc/sidersp/config.yaml`.
After restart, the service uses the configured `logging.app`, `logging.stats`,
and `logging.event` levels.

## Logging

SideSP writes three log channels:

- `logging.app.file_path`: service runtime, startup, shutdown, and failures
- `logging.stats.file_path`: periodic kernel stats snapshots
- `logging.event.file_path`: high-value rule-match events

If the `logging.stats` or `logging.event` block is omitted, that channel reuses
the fully resolved `logging.app` configuration. Once a channel block is
present, it uses its own configured values and its own channel defaults.

The default rotation policy is:

```yaml
logging:
  app:
    level: info
    file_path: /var/log/sidersp/sidersp.log
    max_size_mb: 100
    max_backups: 7
    max_age_days: 30
    compress: true
  stats:
    level: info
    file_path: /var/log/sidersp/sidersp.stats.log
    max_size_mb: 100
    max_backups: 7
    max_age_days: 30
    compress: true
  event:
    level: info
    file_path: /var/log/sidersp/sidersp.event.log
    max_size_mb: 100
    max_backups: 7
    max_age_days: 30
    compress: true
```

The legacy `GET/PUT /api/v1/logging/level` endpoints remain compatible and
continue to read and modify only the `app` channel.

When file logging is configured, SideSP writes application logs to the log
files and does not duplicate them to journald. Use `systemctl status sidersp`
for service state and the log files for application diagnostics.

Restart after config or rule changes:

```bash
sudo systemctl restart sidersp
```

## Upgrade

Build or unpack the new release package, then reinstall and restart:

```bash
sudo scripts/install-systemd.sh
sudo systemctl restart sidersp
```

This preserves existing config and rules unless `--force` is passed.

## Roll Back

Unpack a known-good release package, then reinstall and restart:

```bash
sudo scripts/install-systemd.sh
sudo systemctl restart sidersp
```

If config or rules changed, restore the previous files under `/etc/sidersp` and
restart the service.

## Uninstall

Remove the unit and binary while preserving config and rules:

```bash
sudo scripts/uninstall-systemd.sh
```

Remove config and rules as well:

```bash
sudo scripts/uninstall-systemd.sh --purge-config
```

Preview removal:

```bash
scripts/uninstall-systemd.sh --dry-run
```
