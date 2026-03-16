from fortipot.config import Settings
from fortipot.models import SourceClassification
from fortipot.utils.ip import classify_ip


def test_classify_private_ip() -> None:
    settings = Settings()
    assert classify_ip("10.1.2.3", settings) == SourceClassification.PRIVATE


def test_classify_public_ip() -> None:
    settings = Settings()
    assert classify_ip("8.8.8.8", settings) == SourceClassification.PUBLIC


def test_classify_allowlisted_ip() -> None:
    settings = Settings.model_validate({"allowlists": {"ips": ["10.1.2.3"]}})
    assert classify_ip("10.1.2.3", settings) == SourceClassification.ALLOWLISTED
