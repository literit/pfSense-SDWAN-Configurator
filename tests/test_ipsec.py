import sys
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
def test_returns_tuple_of_two() -> None:
    result = make_ipsec_phases(_make_tunnel(), "ikev2")
    assert isinstance(result, tuple)
    assert len(result) == 2


def test_phase1_key_attributes() -> None:
    tunnel = _make_tunnel()
    phase1, _ = make_ipsec_phases(tunnel, "ikev2")
    assert phase1.descr == tunnel["name"]
    assert phase1.interface == tunnel["interface"]
    assert phase1.remote_gateway == tunnel["remote_gateway"]
    assert phase1.pre_shared_key == tunnel["pre_shared_key"]


def test_phase1_security_settings() -> None:
    phase1, _ = make_ipsec_phases(_make_tunnel(), "ikev2")
    assert phase1.disabled is False
    assert phase1.authentication_method == "pre_shared_key"
    assert phase1.lifetime == 28800
    assert phase1.nat_traversal == "on"
    assert phase1.mobike == "off"
    assert phase1.dpd_delay == 10
    assert phase1.dpd_maxfail == 5


def test_phase2_key_attributes() -> None:
    tunnel = _make_tunnel()
    _, phase2 = make_ipsec_phases(tunnel, "ikev2")
    assert phase2.mode == "vti"
    assert phase2.protocol == "esp"
    assert phase2.descr == tunnel["name"]
    assert phase2.disabled is False


def test_phase2_lifetime_and_rekey() -> None:
    _, phase2 = make_ipsec_phases(_make_tunnel(), "ikev2")
    assert phase2.lifetime == 3600
    assert phase2.rekey_time == 0
    assert phase2.rand_time == 0
    assert phase2.keepalive is False
    assert phase2.mobile is False


@pytest.mark.parametrize("ike_version", ["ikev1", "ikev2"])
def test_different_ike_versions(ike_version: str) -> None:
    result = make_ipsec_phases(_make_tunnel(), ike_version)
    assert len(result) == 2


def test_returns_calls_per_firewall() -> None:
    calls, _ = build_ipsec_calls(_make_tunnels_by_firewall(), "ikev2", _tunnel_index())
    assert "fw1" in calls
    assert "fw2" in calls
    assert len(calls["fw1"]) == 1
    assert len(calls["fw2"]) == 1


def test_tunnel_index_updated_with_phase2() -> None:
    _, index = build_ipsec_calls(_make_tunnels_by_firewall(), "ikev2", _tunnel_index())
    assert "phase2" in index["fw1"]["tunnel-a"]
    assert "phase2" in index["fw2"]["tunnel-b"]


def test_empty_firewalls() -> None:
    calls, index = build_ipsec_calls({}, "ikev2", {})
    assert calls == {}
    assert index == {}


def test_phase1_objects_are_in_calls_list() -> None:
    calls, _ = build_ipsec_calls(_make_tunnels_by_firewall(), "ikev2", _tunnel_index())
    assert calls["fw1"][0] is not None
    assert calls["fw2"][0] is not None
