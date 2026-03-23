import sys
from types import SimpleNamespace
from unittest.mock import ANY, MagicMock

import pytest


for _mod in [
    "pfapi",
    "pfapi.models",
    "pfapi.api",
    "pfapi.api.mim",
    "pfapi.api.interfaces",
    "pfapi.api.vpn",
    "pfapi.api.system",
]:
    sys.modules.setdefault(_mod, MagicMock())

from src.devices import (  # noqa: E402
    apply_changes_to_all_devices,
    apply_tunnels_to_devices,
    build_device_children,
    turn_on_ipsec_tunnels,
)
from src.devices import (  # noqa: E402
    add_interface,
    apply_dirty_config,
    get_ip_sec_phases,
    get_interface_descriptors,
    get_interfaces,
    set_ip_sec_phase_1,
    set_ip_sec_phase_2,
)


def test_build_device_children_excludes_localhost() -> None:
    localhost = SimpleNamespace(name="local", device_id="localhost")
    remote = SimpleNamespace(name="fw-a", device_id="dev-a")
    controlled_devices = SimpleNamespace(devices=[localhost, remote])

    session_client = MagicMock()
    session_client.call.return_value = controlled_devices
    session_client.createDeviceApiChild.return_value = "child-a"

    children = build_device_children(session_client)

    assert children == {"fw-a": "child-a"}
    session_client.createDeviceApiChild.assert_called_once_with(device_id="dev-a")


def test_build_device_children_raises_when_no_remote_devices() -> None:
    localhost = SimpleNamespace(name="local", device_id="localhost")
    controlled_devices = SimpleNamespace(devices=[localhost])

    session_client = MagicMock()
    session_client.call.return_value = controlled_devices

    with pytest.raises(Exception, match="No online devices"):
        build_device_children(session_client)


def test_apply_tunnels_to_devices_dry_run_skips_api_calls() -> None:
    child = MagicMock()
    tunnel = SimpleNamespace(interface="wan", descr="t1")

    apply_tunnels_to_devices(
        device_children={"fw1": child},
        ipsectunnelcalls={"fw1": [tunnel]},
        tunnel_index={"fw1": {"t1": {"phase2": SimpleNamespace(ikeid=None)}}},
        dry_run=True,
    )

    child.call.assert_not_called()


def test_apply_tunnels_to_devices_sets_ikeid_and_phase2_calls() -> None:
    child = MagicMock()

    interfaces_response = MagicMock()
    interfaces_response.to_dict.return_value = {
        "interfaces": [{"assigned": "wan", "identity": "wan-id"}]
    }

    phase1_response = MagicMock()
    phase1_response.to_dict.return_value = {"msg": "Phase1 42 saved"}

    existing_phases_response = MagicMock()
    existing_phases_response.to_dict.return_value = {"data": {"phase_1": []}}

    child.call.side_effect = [interfaces_response, existing_phases_response, phase1_response, None]

    phase1 = SimpleNamespace(interface="wan", descr="tun-a")
    phase2 = SimpleNamespace(ikeid=None)

    tunnel_index = {"fw1": {"tun-a": {"phase2": phase2}}}

    apply_tunnels_to_devices(
        device_children={"fw1": child},
        ipsectunnelcalls={"fw1": [phase1]},
        tunnel_index=tunnel_index,
        dry_run=False,
    )

    assert phase1.interface == "wan-id"
    assert phase2.ikeid == "42"
    child.call.assert_any_call(get_ip_sec_phases.sync)
    child.call.assert_any_call(set_ip_sec_phase_2.sync, body=phase2)


def test_apply_tunnels_to_devices_skips_existing_phase1() -> None:
    child = MagicMock()

    interfaces_response = MagicMock()
    interfaces_response.to_dict.return_value = {
        "interfaces": [{"assigned": "wan", "identity": "wan-id"}]
    }

    existing_phases_response = MagicMock()
    existing_phases_response.to_dict.return_value = {
        "data": {"phase_1": [{"descr": "tun-a", "ikeid": "7"}]}
    }

    child.call.side_effect = [interfaces_response, existing_phases_response, None]

    phase1 = SimpleNamespace(interface="wan", descr="tun-a")
    phase2 = SimpleNamespace(ikeid=None)
    tunnel_index = {"fw1": {"tun-a": {"phase2": phase2}}}

    apply_tunnels_to_devices(
        device_children={"fw1": child},
        ipsectunnelcalls={"fw1": [phase1]},
        tunnel_index=tunnel_index,
        dry_run=False,
    )

    assert phase1.interface == "wan-id"
    assert phase2.ikeid == "7"
    child.call.assert_any_call(get_ip_sec_phases.sync)
    child.call.assert_any_call(set_ip_sec_phase_2.sync, body=phase2)
    assert all(call.args[0] != set_ip_sec_phase_1.sync for call in child.call.call_args_list)


def test_turn_on_ipsec_tunnels_creates_missing_ipsec_interfaces() -> None:
    child = MagicMock()

    interfaces_response = MagicMock()
    interfaces_response.to_dict.return_value = {
        "interfaces": [{"if": "igb0"}]
    }

    add_interface_response = MagicMock()
    add_interface_response.to_dict.return_value = {"assigned": "OPT42"}

    child.call.side_effect = [interfaces_response, add_interface_response]

    phase2 = SimpleNamespace(ikeid="0")
    tunnel_index = {"fw1": {"tun-a": {"phase2": phase2}}}

    turn_on_ipsec_tunnels({"fw1": child}, dry_run=False, tunnel_index=tunnel_index)

    child.call.assert_any_call(get_interfaces.sync)
    child.call.assert_any_call(add_interface.sync, body=ANY)
    assert tunnel_index["fw1"]["tun-a"]["interface_assigned"] == "OPT42"
    assert tunnel_index["fw1"]["tun-a"]["interface_device"] == "ipsec0"
    assert tunnel_index["fw1"]["tun-a"]["interface_identity"] == "opt42"


def test_turn_on_ipsec_tunnels_dry_run_skips_api_calls() -> None:
    child = MagicMock()

    turn_on_ipsec_tunnels({"fw1": child}, dry_run=True, tunnel_index={"fw1": {}})

    child.call.assert_not_called()


def test_apply_changes_to_all_devices_calls_apply_dirty_config() -> None:
    child = MagicMock()

    apply_changes_to_all_devices({"fw1": child}, dry_run=False)

    child.call.assert_any_call(apply_dirty_config.sync, body=ANY)


def test_apply_changes_to_all_devices_dry_run_skips_calls() -> None:
    child = MagicMock()

    apply_changes_to_all_devices({"fw1": child}, dry_run=True)

    child.call.assert_not_called()
