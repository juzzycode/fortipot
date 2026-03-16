# Development Guide

This guide covers local development and contribution workflow for `fortipot`.

## Prerequisites

- Python 3.12+
- `pip` or `uv`
- a writable local virtual environment

## Local Setup

Using `pip`:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .[dev]
```

Using `uv`:

```powershell
uv venv .venv
.\.venv\Scripts\Activate.ps1
uv pip install --python .venv\Scripts\python.exe -e .[dev]
```

## Running Tests

Standard:

```powershell
python -m pytest
```

If Windows temp permissions are noisy in a constrained environment, use an explicit base temp:

```powershell
python -m pytest --basetemp C:\Temp\fortipot-pytest -p no:cacheprovider
```

## Useful Commands

```powershell
fortipot check-config --config config.example.yaml
fortipot simulate --scenario syn_scan --config config.example.yaml
fortipot events list --config config.example.yaml
fortipot actions list --config config.example.yaml
```

## Project Conventions

- keep modules focused and small
- prefer explicit readable code
- use type hints throughout
- write docstrings for public classes and functions
- keep enforcement logic isolated from detection logic
- avoid offensive behavior or active probing

## Where To Extend Next

- richer packet normalization from live capture
- fuller approval replay flow
- persistence for queued approvals and release history
- webhook alerting
- API auth and RBAC
- stronger FortiGate adapters for environment-specific semantics

## Defensive Scope Reminder

This project is for defensive blue-team use only. Contributions should not add:

- exploit capabilities
- credential attacks
- active hostile probing
- internet-scale scanning
- persistence or offensive automation
