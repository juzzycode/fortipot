"""FortiGate client abstraction."""

from __future__ import annotations

import os
from typing import Any

import httpx

from fortipot.config import FortiGateConfig


class FortiGateError(RuntimeError):
    """Raised when FortiGate operations fail."""


class FortiGateClient:
    """Adapter-friendly FortiGate client with conservative defaults."""

    def __init__(self, config: FortiGateConfig, dry_run: bool = True) -> None:
        self.config = config
        self.dry_run = dry_run
        self.token = os.getenv(config.token_env, "")

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def _params(self) -> dict[str, str]:
        return {"vdom": self.config.vdom} if self.config.vdom else {}

    def _request(self, method: str, path: str, json_body: dict[str, Any] | None = None) -> dict[str, Any]:
        if self.dry_run:
            return {"dry_run": True, "method": method, "path": path, "json": json_body or {}}
        url = f"{self.config.base_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            with httpx.Client(
                verify=self.config.verify_tls,
                timeout=self.config.request_timeout_seconds,
            ) as client:
                response = client.request(
                    method,
                    url,
                    headers=self._headers(),
                    params=self._params(),
                    json=json_body,
                )
                response.raise_for_status()
                return response.json() if response.content else {"status": "ok"}
        except httpx.HTTPError as exc:
            raise FortiGateError(str(exc)) from exc

    def quarantine_endpoint(self, *, ip: str, mac: str | None, duration_minutes: int) -> dict[str, Any]:
        """Quarantine a local endpoint.

        Exact FortiGate semantics vary by environment, so the API path is kept
        here and should be lab-validated before production deployment.
        """

        return self._request(
            "POST",
            "/api/v2/cmdb/fortipot/quarantine",
            {"ip": ip, "mac": mac, "duration_minutes": duration_minutes},
        )

    def release_endpoint(self, *, ip: str | None = None, mac: str | None = None) -> dict[str, Any]:
        """Release a quarantined or blocked endpoint."""

        return self._request("POST", "/api/v2/cmdb/fortipot/release", {"ip": ip, "mac": mac})

    def block_public_ip(self, *, ip: str, duration_minutes: int) -> dict[str, Any]:
        """Block a public IP using a conservative wrapper."""

        return self._request(
            "POST",
            "/api/v2/cmdb/fortipot/block-public",
            {"ip": ip, "duration_minutes": duration_minutes},
        )

    def healthcheck(self) -> dict[str, Any]:
        """Check connectivity to the FortiGate API."""

        return self._request("GET", "/api/v2/monitor/system/status")
