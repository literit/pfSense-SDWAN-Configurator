import sys
from types import SimpleNamespace
from unittest.mock import ANY, MagicMock

import pytest


for _mod in [
    "pfapi",
    "pfapi.models",
    "pfapi.api",
    "pfapi.api.login",
    "pfapi.api.mim",
    "pfapi.api.interfaces",
    "pfapi.api.vpn",
    "pfapi.api.system",
]:
    sys.modules.setdefault(_mod, MagicMock())

from src.devices import (  # noqa: E402
    _extract_existing_ipsec_phases,
    apply_changes_to_all_devices,
    apply_tunnels_to_devices,
    build_device_children,
    cleanup_previous_run_ipsec_resources,
    turn_on_ipsec_tunnels,
)
from src.devices import (  # noqa: E402
    add_interface,
    apply_dirty_config,
    delete_interface,
    delete_ip_sec_phase_1,
    delete_ip_sec_phase_2,
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


def test_apply_tunnels_to_devices_skips_existing_phase2() -> None:
    child = MagicMock()

    interfaces_response = MagicMock()
    interfaces_response.to_dict.return_value = {
        "interfaces": [{"assigned": "wan", "identity": "wan-id"}]
    }

    existing_phases_response = MagicMock()
    existing_phases_response.to_dict.return_value = {
        "phase1": [{"descr": "tun-a", "ikeid": "7"}],
        "phase2": [{"descr": "tun-a", "ikeid": "7", "uniqid": "abc"}],
    }

    child.call.side_effect = [interfaces_response, existing_phases_response]

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
    assert all(call.args[0] != set_ip_sec_phase_1.sync for call in child.call.call_args_list)
    assert all(call.args[0] != set_ip_sec_phase_2.sync for call in child.call.call_args_list)


def test_extract_existing_ipsec_phases_returns_normalized_phase_list() -> None:
    response = {
        "phase1": [{"descr": "tun-a", "ikeid": "7"}],
        "phase2": [{"descr": "tun-a", "ikeid": "7", "uniqid": "abc"}],
    }

    existing = _extract_existing_ipsec_phases(response)

    assert existing == [
        {"phase": "phase1", "descr": "tun-a", "ikeid": "7", "uniqid": ""},
        {"phase": "phase2", "descr": "tun-a", "ikeid": "7", "uniqid": "abc"},
    ]


def test_cleanup_previous_run_ipsec_resources_deletes_in_required_order() -> None:
    child = MagicMock()

    phases_response = MagicMock()
    phases_response.to_dict.return_value = {
        "phase1": [
            {"descr": "vpn_tun-a", "ikeid": "7"},
            {"descr": "other_tun", "ikeid": "9"},
        ],
        "phase2": [
            {"descr": "vpn_tun-a", "ikeid": "7", "uniqid": "abc"},
            {"descr": "other_tun", "ikeid": "9", "uniqid": "def"},
        ],
    }

    interfaces_response = MagicMock()
    interfaces_response.to_dict.return_value = {
        "interfaces": [
            {"if": "ipsec7", "identity": "opt7", "descr": "vpn_tun-a"},
            {"if": "ipsec9", "identity": "opt9", "descr": "other_tun"},
        ]
    }

    child.call.side_effect = [phases_response, interfaces_response, None, None, None]

    cleanup_previous_run_ipsec_resources(
        device_children={"fw1": child},
        hint_prefix="vpn",
        dry_run=False,
    )

    assert child.call.call_args_list[0].args[0] == get_ip_sec_phases.sync
    assert child.call.call_args_list[1].args[0] == get_interfaces.sync
    assert child.call.call_args_list[2].args[0] == delete_interface.sync
    assert child.call.call_args_list[2].kwargs == {"name": "opt7"}
    assert child.call.call_args_list[3].args[0] == delete_ip_sec_phase_2.sync
    assert child.call.call_args_list[3].kwargs == {"reqid": "abc"}
    assert child.call.call_args_list[4].args[0] == delete_ip_sec_phase_1.sync
    assert child.call.call_args_list[4].kwargs == {"ikeid": "7"}


def test_cleanup_previous_run_ipsec_resources_deallocates_tunnel_ips() -> None:
    child = MagicMock()

    phases_response = MagicMock()
    phases_response.to_dict.return_value = {
        "phase1": [{"descr": "vpn_tun-a", "ikeid": "7"}],
        "phase2": [{"descr": "vpn_tun-a", "ikeid": "7", "uniqid": "abc"}],
    }

    interfaces_response = MagicMock()
    interfaces_response.to_dict.return_value = {
        "interfaces": [{"if": "ipsec7", "identity": "opt7", "descr": "vpn_tun-a"}]
    }

    child.call.side_effect = [phases_response, interfaces_response, None, None, None]

    allocator = MagicMock()
    tunnel_index = {
        "fw1": {
            "vpn_tun-a": {"tunnel_id": "tag:fw1:wan|tag:fw2:lan"}
        }
    }

    cleanup_previous_run_ipsec_resources(
        device_children={"fw1": child},
        hint_prefix="vpn",
        tunnel_index=tunnel_index,
        allocator=allocator,
        dry_run=False,
    )

    allocator.dealloc.assert_called_once_with("tag:fw1:wan|tag:fw2:lan")


def test_cleanup_previous_run_ipsec_resources_deallocates_once_per_tunnel() -> None:
    child = MagicMock()

    phases_response = MagicMock()
    phases_response.to_dict.return_value = {
        "phase1": [
            {"descr": "vpn_tun-a", "ikeid": "7"},
            {"descr": "vpn_tun-b", "ikeid": "8"},
        ],
        "phase2": [
            {"descr": "vpn_tun-a", "ikeid": "7", "uniqid": "abc"},
            {"descr": "vpn_tun-b", "ikeid": "8", "uniqid": "def"},
        ],
    }

    interfaces_response = MagicMock()
    interfaces_response.to_dict.return_value = {
        "interfaces": [
            {"if": "ipsec7", "identity": "opt7"},
            {"if": "ipsec8", "identity": "opt8"},
        ]
    }

    child.call.side_effect = [
        phases_response,
        interfaces_response,
        None,  # delete opt7
        None,  # delete opt8
        None,  # delete phase2(abc)
        None,  # delete phase2(def)
        None,  # delete phase1(7)
        None,  # delete phase1(8)
    ]

    allocator = MagicMock()
    tunnel_index = {
        "fw1": {
            "vpn_tun-a": {"tunnel_id": "shared-tunnel-id"},
            "vpn_tun-b": {"tunnel_id": "shared-tunnel-id"},
        }
    }

    cleanup_previous_run_ipsec_resources(
        device_children={"fw1": child},
        hint_prefix="vpn",
        tunnel_index=tunnel_index,
        allocator=allocator,
        dry_run=False,
    )

    allocator.dealloc.assert_called_once_with("shared-tunnel-id")


def test_cleanup_previous_run_ipsec_resources_dry_run_skips_api_calls() -> None:
    child = MagicMock()

    cleanup_previous_run_ipsec_resources(
        device_children={"fw1": child},
        hint_prefix="vpn",
        dry_run=True,
    )

    child.call.assert_not_called()


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
