import sys
from typing import Any, cast
from unittest.mock import MagicMock

import pytest

# Mock pfapi and its sub-modules before importing src.ipsec, which
# imports Phase1, Phase2 and related model classes from pfapi.models.
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

from src.ipsec import make_ipsec_phases, build_ipsec_calls  # noqa: E402


def _make_tunnel():
    return {
        "name": "vpn_eth0-fw2-eth1",
        "interface": "eth0",
        "remote_gateway": "2.2.2.2",
        "pre_shared_key": "mysecret",
        "tunnel_ip": "10.0.0.0",
        "remote_tunnel_ip": "10.0.0.1",
    }


def _make_tunnels_by_firewall():
    return {
        "fw1": [
            {
                "name": "tunnel-a",
                "interface": "eth0",
                "remote_gateway": "2.2.2.2",
                "pre_shared_key": "secret",
                "tunnel_ip": "10.0.0.0",
                "remote_tunnel_ip": "10.0.0.1",
            }
        ],
        "fw2": [
            {
                "name": "tunnel-b",
                "interface": "eth1",
                "remote_gateway": "1.1.1.1",
                "pre_shared_key": "secret",
                "tunnel_ip": "10.0.0.1",
                "remote_tunnel_ip": "10.0.0.0",
            }
        ],
    }


def _make_tunnel_index():
    return {
        "fw1": {"tunnel-a": {}},
        "fw2": {"tunnel-b": {}},
    }


# Backwards compatibility alias for existing references, if any.
_tunnel_index = _make_tunnel_index


def _make_ipsec_config(**overrides):
    config = {
        "ike": "ikev2",
        "p1_encryption": "aes",
        "p1_encryption_bits": "128",
        "p1_hash": "sha256",
        "p1_group": "14",
        "p2_encryption": "aes",
        "p2_encryption_bits": "128",
        "p2_hash": "sha256",
        "p2_group": "14",
    }
    config.update(overrides)
    return config


def test_returns_tuple_of_two() -> None:
    result = make_ipsec_phases(_make_tunnel(), _make_ipsec_config())
    assert isinstance(result, tuple)
    assert len(result) == 2


def test_phase1_key_attributes() -> None:
    tunnel = _make_tunnel()
    phase1, _ = make_ipsec_phases(tunnel, _make_ipsec_config())
    assert phase1.descr == tunnel["name"]
    assert phase1.interface == tunnel["interface"]
    assert phase1.remote_gateway == tunnel["remote_gateway"]
    assert phase1.pre_shared_key == tunnel["pre_shared_key"]


def test_phase1_security_settings() -> None:
    phase1, _ = make_ipsec_phases(_make_tunnel(), _make_ipsec_config())
    assert phase1.disabled is False
    assert phase1.authentication_method == "pre_shared_key"
    assert phase1.lifetime == 28800
    assert phase1.nat_traversal == "on"
    assert phase1.mobike == "off"
    assert phase1.dpd_delay == 10
    assert phase1.dpd_maxfail == 5


def test_phase2_key_attributes() -> None:
    tunnel = _make_tunnel()
    _, phase2 = make_ipsec_phases(tunnel, _make_ipsec_config())
    assert phase2.mode == "vti"
    assert phase2.protocol == "esp"
    assert phase2.descr == tunnel["name"]
    assert phase2.disabled is False


def test_phase2_lifetime_and_rekey() -> None:
    _, phase2 = make_ipsec_phases(_make_tunnel(), _make_ipsec_config())
    assert phase2.lifetime == 3600
    assert phase2.rekey_time == 0
    assert phase2.rand_time == 0
    assert phase2.keepalive is False
    assert phase2.mobile is False


@pytest.mark.parametrize("ike_version", ["ikev1", "ikev2"])
def test_different_ike_values_in_config(ike_version: str) -> None:
    result = make_ipsec_phases(_make_tunnel(), _make_ipsec_config(ike=ike_version))
    assert len(result) == 2


def test_returns_calls_per_firewall() -> None:
    calls, _ = build_ipsec_calls(_make_tunnels_by_firewall(), _make_ipsec_config(), _tunnel_index())
    assert "fw1" in calls
    assert "fw2" in calls
    assert len(calls["fw1"]) == 1
    assert len(calls["fw2"]) == 1


def test_tunnel_index_updated_with_phase2() -> None:
    _, index = build_ipsec_calls(_make_tunnels_by_firewall(), _make_ipsec_config(), _tunnel_index())
    assert "phase2" in index["fw1"]["tunnel-a"]
    assert "phase2" in index["fw2"]["tunnel-b"]


def test_empty_firewalls() -> None:
    calls, index = build_ipsec_calls({}, _make_ipsec_config(), {})
    assert calls == {}
    assert index == {}


def test_phase1_objects_are_in_calls_list() -> None:
    calls, _ = build_ipsec_calls(_make_tunnels_by_firewall(), _make_ipsec_config(), _tunnel_index())
    assert calls["fw1"][0] is not None
    assert calls["fw2"][0] is not None


def test_custom_crypto_settings_are_applied(monkeypatch) -> None:
    monkeypatch.setattr("src.ipsec.Phase1Encryption.from_dict", lambda data: data)
    monkeypatch.setattr("src.ipsec.EncryptionAlgorithm.from_dict", lambda data: data)

    phase1, phase2 = make_ipsec_phases(
        _make_tunnel(),
        _make_ipsec_config(
            p1_encryption="aes256gcm",
            p1_encryption_bits="256",
            p1_hash="sha384",
            p1_group="15",
            p2_encryption="aes256gcm",
            p2_encryption_bits="256",
            p2_hash="sha384",
            p2_group="15",
        ),
    )

    phase1_encryption = cast(Any, phase1.encryption)
    assert phase1_encryption["item"][0]["encryption_algorithm"]["name"] == "aes256gcm"
    assert phase1_encryption["item"][0]["encryption_algorithm"]["keylen"] == "256"
    assert phase1_encryption["item"][0]["hash_algorithm"] == "sha384"
    assert phase1_encryption["item"][0]["dhgroup"] == "15"
    assert phase2.encryption_algorithm_option == [{"name": "aes256gcm", "keylen": "256"}]
    assert phase2.hash_algorithm_option == ["sha384"]
    assert phase2.pfsgroup == "15"


def test_build_calls_accepts_ipsec_config_dict(monkeypatch) -> None:
    seen = []

    def _fake_make_ipsec_phases(tunnel, config):
        seen.append((config["ike"], config["p1_encryption"], config["p2_encryption"]))
        return MagicMock(), MagicMock()

    monkeypatch.setattr("src.ipsec.make_ipsec_phases", _fake_make_ipsec_phases)

    build_ipsec_calls(
        _make_tunnels_by_firewall(),
        _make_ipsec_config(ike="ikev1", p1_encryption="aes256gcm", p2_encryption="chacha20poly1305"),
        _tunnel_index(),
    )

    assert seen
    assert all(item[0] == "ikev1" for item in seen)
    assert all(item[1] == "aes256gcm" for item in seen)
    assert all(item[2] == "chacha20poly1305" for item in seen)


def test_invalid_encryption_algorithm_raises() -> None:
    with pytest.raises(ValueError):
        make_ipsec_phases(_make_tunnel(), _make_ipsec_config(p1_encryption="invalid_algo"))


def test_invalid_group_value_raises() -> None:
    with pytest.raises(ValueError):
        make_ipsec_phases(_make_tunnel(), _make_ipsec_config(p2_group="0"))
