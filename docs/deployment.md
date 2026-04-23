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
| Logs | journald, unit `sidersp.service` |

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

## Response AF_XDP Notes

The default example config keeps `response.enabled: false`. If AF_XDP response
workers are enabled, verify queue IDs, NIC support, UMEM sizing, and source
hardware address settings before starting the service. AF_XDP setup failures
will fail service startup and systemd will restart according to the unit policy.

## Operate

Check service state:

```bash
systemctl status sidersp
```

View logs:

```bash
journalctl -u sidersp -n 100
journalctl -u sidersp -f
```

Query the local console API:

```bash
curl http://127.0.0.1:8080/api/v1/status
```

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
