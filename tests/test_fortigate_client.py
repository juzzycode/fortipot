from fortipot.config import FortiGateConfig
from fortipot.enforcer.fortigate import FortiGateClient


def test_fortigate_client_dry_run() -> None:
    client = FortiGateClient(FortiGateConfig(), dry_run=True)
    result = client.quarantine_endpoint(ip="10.0.0.25", mac="aa:bb:cc:dd:ee:ff", duration_minutes=60)
    assert result["dry_run"] is True
    assert result["json"]["ip"] == "10.0.0.25"
