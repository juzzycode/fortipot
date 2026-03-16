"""Configuration loading and validation."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, model_validator

from fortipot.models import EnforcementMode


class AppConfig(BaseModel):
    """Top-level app settings."""

    name: str = "fortipot"
    mode: EnforcementMode = EnforcementMode.DETECT_ONLY
    dry_run: bool = True
    log_level: str = "INFO"


class CaptureConfig(BaseModel):
    """Packet capture settings."""

    interface: str = "eth0"
    promiscuous: bool = True
    bpf_filter: str = ""
    use_pcap: bool = True


class DetectionConfig(BaseModel):
    """Detection thresholds and signal weights."""

    window_seconds: int = 15
    alert_score: int = 25
    isolate_score: int = 50
    syn_scan_ports_threshold: int = 10
    host_fanout_threshold: int = 8
    arp_sweep_threshold: int = 12
    icmp_sweep_threshold: int = 10
    service_fanout_ports: list[int] = Field(default_factory=lambda: [22, 445, 3389, 5985])


class ClassificationConfig(BaseModel):
    """Source classification settings."""

    local_cidrs: list[str] = Field(
        default_factory=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    )
    treat_link_local_as_local: bool = True


class AllowlistConfig(BaseModel):
    """Allowlist and exemption definitions."""

    cidrs: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    macs: list[str] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    exempt_tags: list[str] = Field(default_factory=list)


class SafetyConfig(BaseModel):
    """Safety rail settings for enforcement."""

    auto_release_minutes: int = 60
    cooldown_minutes: int = 30
    max_auto_actions_per_minute: int = 5
    require_mac_for_local_quarantine: bool = True
    min_confidence_for_isolation: float = 0.8

    @model_validator(mode="after")
    def validate_confidence(self) -> "SafetyConfig":
        """Ensure confidence threshold is normalized."""

        if not 0 <= self.min_confidence_for_isolation <= 1:
            raise ValueError("min_confidence_for_isolation must be between 0 and 1")
        return self


class FortiGateConfig(BaseModel):
    """FortiGate integration settings."""

    base_url: str = "https://192.168.1.1"
    token_env: str = "FORTIPOT_FGT_TOKEN"
    vdom: str | None = "root"
    verify_tls: bool = True
    request_timeout_seconds: int = 10
    retries: int = 2


class StorageConfig(BaseModel):
    """Persistence settings."""

    sqlite_path: str = "./fortipot.db"


class AlertsConfig(BaseModel):
    """Alert output settings."""

    stdout: bool = True
    webhook_url: str = ""


class Settings(BaseModel):
    """Root configuration schema."""

    app: AppConfig = Field(default_factory=AppConfig)
    capture: CaptureConfig = Field(default_factory=CaptureConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    classification: ClassificationConfig = Field(default_factory=ClassificationConfig)
    allowlists: AllowlistConfig = Field(default_factory=AllowlistConfig)
    safety: SafetyConfig = Field(default_factory=SafetyConfig)
    fortigate: FortiGateConfig = Field(default_factory=FortiGateConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    alerts: AlertsConfig = Field(default_factory=AlertsConfig)

    def redacted_dict(self) -> dict[str, Any]:
        """Return a redacted config view suitable for APIs."""

        data = self.model_dump()
        data["fortigate"]["token_env"] = "***"
        return data


def _apply_env_overrides(data: dict[str, Any]) -> dict[str, Any]:
    """Apply a small set of environment overrides to config data."""

    overrides = {
        ("app", "mode"): os.getenv("FORTIPOT_MODE"),
        ("app", "dry_run"): os.getenv("FORTIPOT_DRY_RUN"),
        ("app", "log_level"): os.getenv("FORTIPOT_LOG_LEVEL"),
        ("storage", "sqlite_path"): os.getenv("FORTIPOT_SQLITE_PATH"),
    }
    for path, value in overrides.items():
        if value is None:
            continue
        target = data
        for part in path[:-1]:
            target = target.setdefault(part, {})
        if path[-1] == "dry_run":
            target[path[-1]] = value.lower() in {"1", "true", "yes", "on"}
        else:
            target[path[-1]] = value
    return data


def load_settings(config_path: str | Path | None = None) -> Settings:
    """Load settings from YAML with environment overrides."""

    path = Path(config_path or os.getenv("FORTIPOT_CONFIG", "config.example.yaml"))
    raw: dict[str, Any] = {}
    if path.exists():
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return Settings.model_validate(_apply_env_overrides(raw))


@lru_cache(maxsize=4)
def get_settings(config_path: str | Path | None = None) -> Settings:
    """Cached settings accessor for API wiring."""

    return load_settings(config_path)
