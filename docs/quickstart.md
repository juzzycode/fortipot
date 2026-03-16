# Quickstart

`fortipot` is a defensive network tripwire for modern LANs. This quickstart gets a local MVP running in safe, detect-only mode.

## 1. Create a Virtual Environment

Linux or macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If you use `uv`:

```powershell
uv venv .venv
.\.venv\Scripts\Activate.ps1
```

## 2. Install fortipot

Linux or macOS:

```bash
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".[dev]"
```

Windows PowerShell:

```powershell
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".[dev]"
```

## 3. Prepare Config

Start from the included example:

Linux or macOS:

```bash
cp config.example.yaml config.yaml
cp .env.example .env
```

Windows PowerShell:

```powershell
Copy-Item config.example.yaml config.yaml
Copy-Item .env.example .env
```

Recommended first-run settings:

- `app.mode: detect_only`
- `app.dry_run: true`
- `capture.interface`: set this to the interface you want to observe
- `bait.enabled`: keep this `false` until you are ready to expose bait ports
- `storage.sqlite_path`: keep the default or point it to a local writable path

## 4. Validate the Config

```bash
fortipot check-config --config config.yaml
```

## 5. Run Local Health Checks

```bash
fortipot health --config config.yaml
fortipot explain-rules --config config.yaml
fortipot version
```

The version command reports the base release plus a build number when repository history is available, for example `0.1.0.12345`.

## 6. Simulate Detection

This is the safest way to confirm the scoring pipeline works before live capture:

```bash
fortipot simulate --scenario syn_scan --config config.yaml
fortipot simulate --scenario icmp_sweep --config config.yaml
```

## 7. Run the Service

Start the runtime:

```bash
fortipot run --config config.yaml
```

Start the API in a separate shell:

```bash
fortipot api --config config.yaml --host 127.0.0.1 --port 8080
```

## 8. Query the API

```bash
curl http://127.0.0.1:8080/
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/rules
curl http://127.0.0.1:8080/events
curl http://127.0.0.1:8080/actions
curl http://127.0.0.1:8080/config/redacted
```

## 9. Move Toward Enforcement Carefully

Recommended progression:

1. Start in `detect_only`.
2. Review event and action history.
3. Switch to `approval_required`.
4. Lab-validate FortiGate integration.
5. Only then consider `fortigate_quarantine` or `fortigate_block_public`.

## Notes

- Public IPs should be blocked, not VLAN-quarantined.
- Local/private endpoint quarantine works best when MAC and VLAN context are available.
- FortiGate API behavior should always be lab-validated before production rollout.

## Linux Capture Permissions

A Python virtual environment does not grant packet-capture privileges by itself. On Linux, promiscuous capture usually requires `CAP_NET_ADMIN`, and raw capture usually requires `CAP_NET_RAW`.

Recommended options:

### Option 1: Grant Linux Capabilities to Python

Find the real interpreter behind your virtual environment:

```bash
readlink -f .venv/bin/python
```

Grant the needed capabilities once as an administrator:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /full/path/to/python3
getcap /full/path/to/python3
```

Then run `fortipot` normally from the virtual environment:

```bash
source .venv/bin/activate
fortipot run --config config.yaml
```

Notes:

- apply `setcap` to the real interpreter, not the `.venv/bin/python` symlink
- interpreter upgrades may require capabilities to be applied again
- this usually needs admin access once

### Option 2: Use `dumpcap`

This is often the safer non-root model.

Install and configure it once as an administrator:

```bash
sudo apt install wireshark-common
sudo dpkg-reconfigure wireshark-common
sudo usermod -aG wireshark $USER
```

After logging out and back in, members of the `wireshark` group can often capture without running Python as root.

### Option 3: No Admin Access

If you do not have admin access, you generally cannot enable promiscuous capture from the virtual environment alone.

Fallback options:

- run in non-promiscuous mode
- use simulation scenarios
- work from packet capture files
- ask an administrator to grant capabilities or configure `dumpcap`
