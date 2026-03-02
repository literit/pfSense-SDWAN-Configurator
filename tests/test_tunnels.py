from src.tunnels import (
    build_tag_interface_map,
    create_tunnel_name,
    build_ipsec_tunnels,
    build_tunnel_calls,
    build_tunnel_index,
)
from src.ip import TunnelIpAllocator


def _make_data(firewalls):
    return {"firewalls": firewalls}


def _make_two_firewall_tag_map():
    return {
        "wan": [
            {"firewall": "fw1", "interface": "eth0", "ip": "1.1.1.1"},
            {"firewall": "fw2", "interface": "eth1", "ip": "2.2.2.2"},
        ]
    }


def _make_tunnel(fw1="fw1", fw2="fw2"):
    return {
        "tag": "wan",
        "interface1": {
            "firewall": fw1,
            "interface": "eth0",
            "ip": "1.1.1.1",
            "tunnel_name": "vpn_eth0-fw2-eth1",
            "tunnel_ip": "10.0.0.0",
        },
        "interface2": {
            "firewall": fw2,
            "interface": "eth1",
            "ip": "2.2.2.2",
            "tunnel_name": "vpn_eth1-fw1-eth0",
            "tunnel_ip": "10.0.0.1",
        },
        "secret": "mysecret",
    }


def test_create_tunnel_name_basic_format() -> None:
    name = create_tunnel_name("hint", "eth0", "fw2", "eth1")
    assert name == "hint_eth0-fw2-eth1"


def test_create_tunnel_name_empty_prefix() -> None:
    name = create_tunnel_name("", "eth0", "fw2", "eth1")
    assert name == "_eth0-fw2-eth1"


def test_create_tunnel_name_all_components_present() -> None:
    name = create_tunnel_name("vpn", "wan0", "remote-fw", "eth2")
    assert "vpn" in name
    assert "wan0" in name
    assert "remote-fw" in name
    assert "eth2" in name


def test_build_tag_interface_map_single_tag_two_firewalls() -> None:
    data = _make_data([
        {"name": "fw1", "interfaces": [{"name": "eth0", "ip": "1.1.1.1", "tags": ["wan"]}]},
        {"name": "fw2", "interfaces": [{"name": "eth1", "ip": "2.2.2.2", "tags": ["wan"]}]},
    ])
    result = build_tag_interface_map(data)
    assert "wan" in result
    assert len(result["wan"]) == 2
    assert result["wan"][0]["firewall"] == "fw1"
    assert result["wan"][1]["firewall"] == "fw2"


def test_build_tag_interface_map_interface_fields_are_preserved() -> None:
    data = _make_data([
        {"name": "fw1", "interfaces": [{"name": "eth0", "ip": "1.2.3.4", "tags": ["wan"]}]},
    ])
    result = build_tag_interface_map(data)
    entry = result["wan"][0]
    assert entry["firewall"] == "fw1"
    assert entry["interface"] == "eth0"
    assert entry["ip"] == "1.2.3.4"


def test_build_tag_interface_map_multiple_tags_on_one_interface() -> None:
    data = _make_data([
        {"name": "fw1", "interfaces": [
            {"name": "eth0", "ip": "1.1.1.1", "tags": ["wan", "backup"]},
        ]},
        {"name": "fw2", "interfaces": [
            {"name": "eth1", "ip": "2.2.2.2", "tags": ["wan"]},
        ]},
    ])
    result = build_tag_interface_map(data)
    assert "wan" in result
    assert "backup" in result
    assert len(result["wan"]) == 2
    assert len(result["backup"]) == 1


def test_build_tag_interface_map_empty_firewalls() -> None:
    result = build_tag_interface_map({"firewalls": []})
    assert result == {}


def test_build_tag_interface_map_multiple_interfaces_same_tag() -> None:
    data = _make_data([
        {"name": "fw1", "interfaces": [
            {"name": "eth0", "ip": "1.1.1.1", "tags": ["wan"]},
            {"name": "eth1", "ip": "1.1.1.2", "tags": ["wan"]},
        ]},
    ])
    result = build_tag_interface_map(data)
    assert len(result["wan"]) == 2


def test_build_ipsec_tunnels_creates_tunnel_between_different_firewalls() -> None:
    tunnels = build_ipsec_tunnels(_make_two_firewall_tag_map(), "10.0.0.0/24", "vpn")
    assert len(tunnels) == 1
    tunnel = tunnels[0]
    assert tunnel["tag"] == "wan"
    assert "interface1" in tunnel
    assert "interface2" in tunnel
    assert "secret" in tunnel
    assert isinstance(tunnel["secret"], str)


def test_build_ipsec_tunnels_skips_same_firewall_interfaces() -> None:
    tagstointerfaces = {
        "wan": [
            {"firewall": "fw1", "interface": "eth0", "ip": "1.1.1.1"},
            {"firewall": "fw1", "interface": "eth1", "ip": "1.1.1.2"},
        ]
    }
    tunnels = build_ipsec_tunnels(tagstointerfaces, "10.0.0.0/24", "vpn")
    assert len(tunnels) == 0


def test_build_ipsec_tunnels_tunnel_ip_assignment() -> None:
    tunnels = build_ipsec_tunnels(_make_two_firewall_tag_map(), "10.0.0.0/24", "vpn")
    assert tunnels[0]["interface1"]["tunnel_ip"] == "10.0.0.0"
    assert tunnels[0]["interface2"]["tunnel_ip"] == "10.0.0.1"


def test_build_ipsec_tunnels_tunnel_names_are_set() -> None:
    tunnels = build_ipsec_tunnels(_make_two_firewall_tag_map(), "10.0.0.0/24", "vpn")
    assert "tunnel_name" in tunnels[0]["interface1"]
    assert "tunnel_name" in tunnels[0]["interface2"]
    assert "vpn" in tunnels[0]["interface1"]["tunnel_name"]


def test_build_ipsec_tunnels_multiple_tags_creates_separate_tunnels() -> None:
    tagstointerfaces = {
        "wan": [
            {"firewall": "fw1", "interface": "eth0", "ip": "1.1.1.1"},
            {"firewall": "fw2", "interface": "eth1", "ip": "2.2.2.2"},
        ],
        "backup": [
            {"firewall": "fw1", "interface": "eth2", "ip": "3.3.3.3"},
            {"firewall": "fw2", "interface": "eth3", "ip": "4.4.4.4"},
        ],
    }
    tunnels = build_ipsec_tunnels(tagstointerfaces, "10.0.0.0/24", "vpn")
    assert len(tunnels) == 2


def test_build_ipsec_tunnels_ip_counter_advances_across_tunnels() -> None:
    tagstointerfaces = {
        "wan": [
            {"firewall": "fw1", "interface": "eth0", "ip": "1.1.1.1"},
            {"firewall": "fw2", "interface": "eth1", "ip": "2.2.2.2"},
        ],
        "backup": [
            {"firewall": "fw1", "interface": "eth2", "ip": "3.3.3.3"},
            {"firewall": "fw2", "interface": "eth3", "ip": "4.4.4.4"},
        ],
    }
    tunnels = build_ipsec_tunnels(tagstointerfaces, "10.0.0.0/24", "vpn")
    ips = [
        tunnels[0]["interface1"]["tunnel_ip"],
        tunnels[0]["interface2"]["tunnel_ip"],
        tunnels[1]["interface1"]["tunnel_ip"],
        tunnels[1]["interface2"]["tunnel_ip"],
    ]
    # Ensure four unique tunnel IPs are assigned
    assert len(set(ips)) == 4
    # Ensure the IP counter advances sequentially within 10.0.0.0/24
    expected = ["10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"]
    for assigned, exp in zip(ips, expected):
        assert exp in assigned


def test_build_ipsec_tunnels_empty_tags_returns_empty() -> None:
    tunnels = build_ipsec_tunnels({}, "10.0.0.0/24", "vpn")
    assert tunnels == []


def test_build_ipsec_tunnels_uses_provided_allocator() -> None:
    allocator = TunnelIpAllocator.init_db("10.0.0.0/24")
    allocator.alloc("pre-existing")

    tunnels = build_ipsec_tunnels(
        _make_two_firewall_tag_map(),
        "10.0.0.0/24",
        "vpn",
        ip_allocator=allocator,
    )

    assert tunnels[0]["interface1"]["tunnel_ip"] == "10.0.0.2"
    assert tunnels[0]["interface2"]["tunnel_ip"] == "10.0.0.3"


def test_build_ipsec_tunnels_allocator_keeps_stable_tunnel_pair() -> None:
    allocator = TunnelIpAllocator.init_db("10.0.0.0/24")

    first = build_ipsec_tunnels(
        _make_two_firewall_tag_map(),
        "10.0.0.0/24",
        "vpn",
        ip_allocator=allocator,
    )
    second = build_ipsec_tunnels(
        _make_two_firewall_tag_map(),
        "10.0.0.0/24",
        "vpn",
        ip_allocator=allocator,
    )

    assert first[0]["interface1"]["tunnel_ip"] == second[0]["interface1"]["tunnel_ip"]
    assert first[0]["interface2"]["tunnel_ip"] == second[0]["interface2"]["tunnel_ip"]


def test_build_tunnel_calls_basic_structure() -> None:
    firewalls = [{"name": "fw1"}, {"name": "fw2"}]
    result = build_tunnel_calls([_make_tunnel()], firewalls)
    assert "fw1" in result
    assert "fw2" in result
    assert len(result["fw1"]) == 1
    assert len(result["fw2"]) == 1


def test_build_tunnel_calls_call_details_fw1() -> None:
    firewalls = [{"name": "fw1"}, {"name": "fw2"}]
    result = build_tunnel_calls([_make_tunnel()], firewalls)
    call = result["fw1"][0]
    assert call["name"] == "vpn_eth0-fw2-eth1"
    assert call["interface"] == "eth0"
    assert call["remote_gateway"] == "2.2.2.2"
    assert call["pre_shared_key"] == "mysecret"
    assert call["tunnel_ip"] == "10.0.0.0"
    assert call["remote_tunnel_ip"] == "10.0.0.1"


def test_build_tunnel_calls_call_details_fw2() -> None:
    firewalls = [{"name": "fw1"}, {"name": "fw2"}]
    result = build_tunnel_calls([_make_tunnel()], firewalls)
    call = result["fw2"][0]
    assert call["name"] == "vpn_eth1-fw1-eth0"
    assert call["interface"] == "eth1"
    assert call["remote_gateway"] == "1.1.1.1"
    assert call["tunnel_ip"] == "10.0.0.1"
    assert call["remote_tunnel_ip"] == "10.0.0.0"


def test_build_tunnel_calls_empty_tunnels() -> None:
    firewalls = [{"name": "fw1"}, {"name": "fw2"}]
    result = build_tunnel_calls([], firewalls)
    assert result == {"fw1": [], "fw2": []}


def test_build_tunnel_calls_multiple_tunnels_same_firewall() -> None:
    firewalls = [{"name": "fw1"}, {"name": "fw2"}]
    tunnels = [_make_tunnel(), _make_tunnel()]
    result = build_tunnel_calls(tunnels, firewalls)
    assert len(result["fw1"]) == 2
    assert len(result["fw2"]) == 2


def test_build_tunnel_index_basic_index() -> None:
    tunnels_by_fw = {
        "fw1": [
            {"name": "tunnel-a", "interface": "eth0"},
            {"name": "tunnel-b", "interface": "eth1"},
        ],
        "fw2": [
            {"name": "tunnel-c", "interface": "eth2"},
        ],
    }
    index = build_tunnel_index(tunnels_by_fw)
    assert "fw1" in index
    assert "tunnel-a" in index["fw1"]
    assert index["fw1"]["tunnel-a"]["interface"] == "eth0"
    assert "tunnel-b" in index["fw1"]
    assert "fw2" in index
    assert "tunnel-c" in index["fw2"]


def test_build_tunnel_index_empty_firewalls() -> None:
    index = build_tunnel_index({})
    assert index == {}


def test_build_tunnel_index_all_tunnel_fields_preserved() -> None:
    tunnels_by_fw = {
        "fw1": [
            {"name": "t1", "interface": "eth0", "remote_gateway": "1.2.3.4", "pre_shared_key": "s"},
        ],
    }
    index = build_tunnel_index(tunnels_by_fw)
    assert index["fw1"]["t1"]["remote_gateway"] == "1.2.3.4"
    assert index["fw1"]["t1"]["pre_shared_key"] == "s"
