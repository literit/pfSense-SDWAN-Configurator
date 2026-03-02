import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock

import pytest

# Mock pfapi and its sub-modules before importing src.config, which
# transitively imports src.helper_funcs (which requires pfapi).
for _mod in [
    "pfapi",
    "pfapi.models",
    "pfapi.api",
    "pfapi.api.login",
    "pfapi.api.mim",
    "pfapi.api.system",
    "pfapi.api.interfaces",
    "pfapi.api.vpn",
]:
    sys.modules.setdefault(_mod, MagicMock())

from src.config import validate_config, load_config  # noqa: E402


def _valid_config():
    return {
        "api_server": "10.0.0.1",
        "firewalls": [{"name": "fw1"}],
        "tunnels_network": "10.0.0.0/24",
        "hint_prefix": "vpn",
        "ipsec": {"ike": "ikev2"},
    }


def _write_yaml(tmpdir, content: str) -> str:
    path = Path(tmpdir) / "config.yaml"
    path.write_text(content)
    return str(path)


def test_valid_config_passes() -> None:
    validate_config(_valid_config())


@pytest.mark.parametrize("missing_field", ["api_server", "firewalls", "tunnels_network", "hint_prefix", "ipsec"])
def test_each_required_field_is_checked(missing_field: str) -> None:
    config = _valid_config()
    del config[missing_field]
    with pytest.raises(ValueError):
        validate_config(config)


def test_missing_multiple_fields() -> None:
    with pytest.raises(ValueError):
        validate_config({})


def test_empty_firewalls_raises() -> None:
    config = _valid_config()
    config["firewalls"] = []
    with pytest.raises(ValueError):
        validate_config(config)


def test_non_empty_firewalls_passes() -> None:
    config = _valid_config()
    config["firewalls"] = [{"name": "fw1"}, {"name": "fw2"}]
    validate_config(config)


def test_load_valid_config() -> None:
    valid_yaml = (
        "api_server: 10.0.0.1\n"
        "firewalls:\n"
        "  - name: fw1\n"
        "tunnels_network: 10.0.0.0/24\n"
        "hint_prefix: vpn\n"
        "ipsec:\n"
        "  ike: ikev2\n"
    )
    with TemporaryDirectory() as tmpdir:
        path = _write_yaml(tmpdir, valid_yaml)
        config = load_config(path)
        assert config["api_server"] == "10.0.0.1"
        assert config["hint_prefix"] == "vpn"
        assert config["tunnels_network"] == "10.0.0.0/24"


def test_load_missing_file_raises() -> None:
    with pytest.raises(FileNotFoundError):
        load_config("/nonexistent/path/config.yaml")


def test_load_config_runs_validation() -> None:
    with TemporaryDirectory() as tmpdir:
        path = _write_yaml(tmpdir, "api_server: 10.0.0.1\n")
        with pytest.raises(ValueError):
            load_config(path)


def test_load_malformed_yaml_raises() -> None:
    import yaml

    with TemporaryDirectory() as tmpdir:
        path = _write_yaml(tmpdir, "key: [unclosed\n")
        with pytest.raises(yaml.YAMLError):
            load_config(path)
