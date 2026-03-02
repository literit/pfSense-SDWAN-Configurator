import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock

import pytest


for _mod in [
    "pfapi",
    "pfapi.models",
    "pfapi.api",
    "pfapi.api.login",
    "pfapi.api.mim",
    "pfapi.api.system",
]:
    sys.modules.setdefault(_mod, MagicMock())

from src import helper_funcs as hf  # noqa: E402


def test_get_settings_uses_defaults_and_password_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["prog"])
    monkeypatch.setenv("PASSWORD", "env-secret")

    settings = hf.get_settings()

    assert settings.USER == "admin"
    assert settings.PASSWORD == "env-secret"
    assert settings.CONTROLLER_URL.startswith("https://")
    assert settings.TAGS == ""


def test_get_settings_reads_config_and_tags(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config_path = tmp_path / "app.conf"
    config_path.write_text(
        "CONTROLLER_URL=https://controller.local:8443\n"
        "USER=test-user\n"
        "PASSWORD=file-secret\n"
    )

    monkeypatch.delenv("PASSWORD", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        ["prog", "-c", str(config_path), "tag-a", "tag-b"],
    )

    settings = hf.get_settings()

    assert settings.USER == "test-user"
    assert settings.PASSWORD == "file-secret"
    assert settings.CONTROLLER_URL == "https://controller.local:8443"
    assert settings.TAGS == "tag-a,tag-b"


def test_get_settings_exits_when_password_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["prog"])
    monkeypatch.delenv("PASSWORD", raising=False)

    with pytest.raises(SystemExit):
        hf.get_settings()


def test_create_device_api_child_returns_none_without_token() -> None:
    client = hf.RequestClient()
    assert client.createDeviceApiChild("dev-1") is None


def test_create_device_api_child_builds_child(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeAuthClient:
        def __init__(self, **kwargs):
            self.base_url = kwargs["base_url"]
            self.cookies = kwargs["cookies"]
            self.token = kwargs["token"]
            self.timeout = None

        def with_timeout(self, timeout):
            self.timeout = timeout
            return self

    monkeypatch.setattr(hf, "AuthenticatedClient", FakeAuthClient)

    parent = hf.RequestClient(controller_url="https://controller")
    parent.token = "abc123"
    parent.cookies = cast(Any, MagicMock())

    child = parent.createDeviceApiChild("device-42", timeout=55)

    assert child is not None
    assert child.parent is parent
    assert child.device_id == "device-42"
    assert child.client is not None
    assert "/api/device/pfsense/device-42/api" in getattr(child.client, "base_url")
    assert child in parent.children


def test_clone_uses_device_specific_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeAuthClient:
        def __init__(self, **kwargs):
            self.base_url = kwargs["base_url"]

        def with_timeout(self, timeout):
            return self

    monkeypatch.setattr(hf, "AuthenticatedClient", FakeAuthClient)

    client = hf.RequestClient(controller_url="https://controller")
    client.token = "token"
    client.cookies = cast(Any, MagicMock())
    client.device_id = "device-11"

    clone = client.clone(timeout=20)

    assert clone.client is not None
    assert getattr(clone.client, "base_url").endswith("/api/device/pfsense/device-11/api")


def test_call_injects_client_argument() -> None:
    client = hf.RequestClient()
    client.client = cast(Any, MagicMock())

    def fake_api(**kwargs):
        return kwargs

    result = client.call(fake_api, body={"k": "v"})

    assert result["client"] is client.client
    assert result["body"] == {"k": "v"}


def test_call_async_passes_result_to_callback() -> None:
    client = hf.RequestClient()
    client.client = cast(Any, MagicMock())
    results = []

    async def fake_async(**kwargs):
        assert kwargs["client"] is client.client
        return SimpleNamespace(ok=True)

    def callback(result):
        results.append(result.ok)

    client.call_async(callback, fake_async)

    assert results == [True]
