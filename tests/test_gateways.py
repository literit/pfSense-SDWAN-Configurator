import sys
from types import SimpleNamespace
from unittest.mock import MagicMock


for _mod in [
    "pfapi",
    "pfapi.models",
    "pfapi.api",
    "pfapi.api.interfaces",
    "pfapi.api.system",
]:
    sys.modules.setdefault(_mod, MagicMock())

from src.gateways import apply_gateways_to_devices  # noqa: E402


class _FakeGateway:
    def __init__(self, gateway: str):
        self.gateway = gateway
        self.additional = {}

    def __setitem__(self, key: str, value):
        self.additional[key] = value


def test_apply_gateways_to_devices_dry_run_skips_api_calls() -> None:
    child = MagicMock()

    apply_gateways_to_devices(
        device_children={"fw1": child},
        tunnel_index={"fw1": {"tun-a": {"phase2": SimpleNamespace(ikeid="9")}}},
        dry_run=True,
    )

    child.call.assert_not_called()


def test_apply_gateways_to_devices_creates_gateway_from_phase2_remoteid(monkeypatch) -> None:
    interfaces_response = MagicMock()
    interfaces_response.to_dict.return_value = {
        "interfaces": [
            {
                "if": "ipsec9",
                "assigned": "OPT9",
                "identity": "opt9",
            }
        ]
    }

    child = MagicMock()
    child.call.side_effect = [interfaces_response, None]

    get_interfaces_sync = object()
    add_gateway_sync = object()

    monkeypatch.setattr("src.gateways.get_interfaces", SimpleNamespace(sync=get_interfaces_sync))
    monkeypatch.setattr("src.gateways.add_gateway", SimpleNamespace(sync=add_gateway_sync))
    monkeypatch.setattr("src.gateways.Gateway", _FakeGateway)

    phase2 = SimpleNamespace(
        ikeid="9",
        remoteid=SimpleNamespace(address="169.254.0.14"),
    )

    apply_gateways_to_devices(
        device_children={"fw1": child},
        tunnel_index={
            "fw1": {
                "test1": {
                    "phase2": phase2,
                    "remote_tunnel_ip": "169.254.0.99",
                }
            }
        },
    )

    _, kwargs = child.call.call_args_list[1]
    body = kwargs["body"]

    assert body.gateway == "169.254.0.14"
    assert body.name == "test1"
    assert body.interface_device == "ipsec9"
    assert body.interface_identity == "opt9"
    assert body.interface_assigned == "OPT9"
    assert body.ipprotocol == "inet"
    assert body.disabled is False
    assert body.monitor_disable is False
    assert body.action_disable is False
    assert body.nonlocalgateway is False
    assert body.additional["dpinger_dont_add_static_route"] is False
    assert body.additional["force_down"] is False
    assert body.additional["_show_advanced"] is True


def test_apply_gateways_to_devices_falls_back_to_remote_tunnel_ip(monkeypatch) -> None:
    interfaces_response = MagicMock()
    interfaces_response.to_dict.return_value = {"interfaces": []}

    child = MagicMock()
    child.call.side_effect = [interfaces_response, None]

    get_interfaces_sync = object()
    add_gateway_sync = object()

    monkeypatch.setattr("src.gateways.get_interfaces", SimpleNamespace(sync=get_interfaces_sync))
    monkeypatch.setattr("src.gateways.add_gateway", SimpleNamespace(sync=add_gateway_sync))
    monkeypatch.setattr("src.gateways.Gateway", _FakeGateway)

    phase2 = SimpleNamespace(ikeid="7", remoteid=None)

    apply_gateways_to_devices(
        device_children={"fw1": child},
        tunnel_index={
            "fw1": {
                "test2": {
                    "phase2": phase2,
                    "remote_tunnel_ip": "169.254.0.22",
                }
            }
        },
    )

    _, kwargs = child.call.call_args_list[1]
    body = kwargs["body"]

    assert body.gateway == "169.254.0.22"
    assert body.interface_device == "ipsec7"
    assert body.interface_identity == "opt7"
    assert body.interface_assigned == "OPT7"
