from fortipot import __version_base__, get_version


def test_get_version_uses_env_build_number(monkeypatch) -> None:
    monkeypatch.setenv("FORTIPOT_BUILD_NUMBER", "12345")
    get_version.cache_clear()
    assert get_version() == f"{__version_base__}.12345"
    get_version.cache_clear()
