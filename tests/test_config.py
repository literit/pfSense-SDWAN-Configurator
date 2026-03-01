import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock

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


class ValidateConfigTests(unittest.TestCase):
    def _valid_config(self):
        return {
            "api_server": "10.0.0.1",
            "firewalls": [{"name": "fw1"}],
            "tunnels_network": "10.0.0.0/24",
            "hint_prefix": "vpn",
            "ipsec": {"ike": "ikev2"},
        }

    def test_valid_config_passes(self) -> None:
        validate_config(self._valid_config())  # should not raise

    def test_each_required_field_is_checked(self) -> None:
        for field in ["api_server", "firewalls", "tunnels_network", "hint_prefix", "ipsec"]:
            with self.subTest(missing=field):
                config = self._valid_config()
                del config[field]
                with self.assertRaises(ValueError):
                    validate_config(config)

    def test_missing_multiple_fields(self) -> None:
        with self.assertRaises(ValueError):
            validate_config({})

    def test_empty_firewalls_raises(self) -> None:
        config = self._valid_config()
        config["firewalls"] = []
        with self.assertRaises(ValueError):
            validate_config(config)

    def test_non_empty_firewalls_passes(self) -> None:
        config = self._valid_config()
        config["firewalls"] = [{"name": "fw1"}, {"name": "fw2"}]
        validate_config(config)  # should not raise


class LoadConfigTests(unittest.TestCase):
    _VALID_YAML = (
        "api_server: 10.0.0.1\n"
        "firewalls:\n"
        "  - name: fw1\n"
        "tunnels_network: 10.0.0.0/24\n"
        "hint_prefix: vpn\n"
        "ipsec:\n"
        "  ike: ikev2\n"
    )

    def _write_yaml(self, tmpdir, content: str) -> str:
        path = Path(tmpdir) / "config.yaml"
        path.write_text(content)
        return str(path)

    def test_load_valid_config(self) -> None:
        with TemporaryDirectory() as tmpdir:
            path = self._write_yaml(tmpdir, self._VALID_YAML)
            config = load_config(path)
            self.assertEqual(config["api_server"], "10.0.0.1")
            self.assertEqual(config["hint_prefix"], "vpn")
            self.assertEqual(config["tunnels_network"], "10.0.0.0/24")

    def test_load_missing_file_raises(self) -> None:
        with self.assertRaises(FileNotFoundError):
            load_config("/nonexistent/path/config.yaml")

    def test_load_config_runs_validation(self) -> None:
        # A YAML file that is syntactically valid but missing required fields
        # should raise ValueError from validate_config.
        with TemporaryDirectory() as tmpdir:
            path = self._write_yaml(tmpdir, "api_server: 10.0.0.1\n")
            with self.assertRaises(ValueError):
                load_config(path)

    def test_load_malformed_yaml_raises(self) -> None:
        import yaml
        with TemporaryDirectory() as tmpdir:
            # An unclosed flow sequence is definitely invalid YAML.
            path = self._write_yaml(tmpdir, "key: [unclosed\n")
            with self.assertRaises(yaml.YAMLError):
                load_config(path)


if __name__ == "__main__":
    unittest.main()
