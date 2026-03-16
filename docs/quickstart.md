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
- `storage.sqlite_path`: keep the default or point it to a local writable path

## 4. Validate the Config

```bash
fortipot check-config --config config.yaml
```

## 5. Run Local Health Checks

```bash
fortipot health --config config.yaml
fortipot version
```

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

```powershell
curl http://127.0.0.1:8080/health
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
