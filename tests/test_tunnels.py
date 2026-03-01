import unittest

from src.tunnels import (
    build_tag_interface_map,
    create_tunnel_name,
    build_ipsec_tunnels,
    build_tunnel_calls,
    build_tunnel_index,
)


class CreateTunnelNameTests(unittest.TestCase):
    def test_basic_format(self) -> None:
        name = create_tunnel_name("hint", "eth0", "fw2", "eth1")
        self.assertEqual(name, "hint_eth0-fw2-eth1")

    def test_empty_prefix(self) -> None:
        name = create_tunnel_name("", "eth0", "fw2", "eth1")
        self.assertEqual(name, "_eth0-fw2-eth1")

    def test_all_components_present(self) -> None:
        name = create_tunnel_name("vpn", "wan0", "remote-fw", "eth2")
        self.assertIn("vpn", name)
        self.assertIn("wan0", name)
        self.assertIn("remote-fw", name)
        self.assertIn("eth2", name)


class BuildTagInterfaceMapTests(unittest.TestCase):
    def _make_data(self, firewalls):
        return {"firewalls": firewalls}

    def test_single_tag_two_firewalls(self) -> None:
        data = self._make_data([
            {"name": "fw1", "interfaces": [{"name": "eth0", "ip": "1.1.1.1", "tags": ["wan"]}]},
            {"name": "fw2", "interfaces": [{"name": "eth1", "ip": "2.2.2.2", "tags": ["wan"]}]},
        ])
        result = build_tag_interface_map(data)
        self.assertIn("wan", result)
        self.assertEqual(len(result["wan"]), 2)
        self.assertEqual(result["wan"][0]["firewall"], "fw1")
        self.assertEqual(result["wan"][1]["firewall"], "fw2")

    def test_interface_fields_are_preserved(self) -> None:
        data = self._make_data([
            {"name": "fw1", "interfaces": [{"name": "eth0", "ip": "1.2.3.4", "tags": ["wan"]}]},
        ])
        result = build_tag_interface_map(data)
        entry = result["wan"][0]
        self.assertEqual(entry["firewall"], "fw1")
        self.assertEqual(entry["interface"], "eth0")
        self.assertEqual(entry["ip"], "1.2.3.4")

    def test_multiple_tags_on_one_interface(self) -> None:
        data = self._make_data([
            {"name": "fw1", "interfaces": [
                {"name": "eth0", "ip": "1.1.1.1", "tags": ["wan", "backup"]},
            ]},
            {"name": "fw2", "interfaces": [
                {"name": "eth1", "ip": "2.2.2.2", "tags": ["wan"]},
            ]},
        ])
        result = build_tag_interface_map(data)
        self.assertIn("wan", result)
        self.assertIn("backup", result)
        self.assertEqual(len(result["wan"]), 2)
        self.assertEqual(len(result["backup"]), 1)

    def test_empty_firewalls(self) -> None:
        result = build_tag_interface_map({"firewalls": []})
        self.assertEqual(result, {})

    def test_multiple_interfaces_same_tag(self) -> None:
        data = self._make_data([
            {"name": "fw1", "interfaces": [
                {"name": "eth0", "ip": "1.1.1.1", "tags": ["wan"]},
                {"name": "eth1", "ip": "1.1.1.2", "tags": ["wan"]},
            ]},
        ])
        result = build_tag_interface_map(data)
        self.assertEqual(len(result["wan"]), 2)


class BuildIpsecTunnelsTests(unittest.TestCase):
    def _make_two_firewall_tag_map(self):
        return {
            "wan": [
                {"firewall": "fw1", "interface": "eth0", "ip": "1.1.1.1"},
                {"firewall": "fw2", "interface": "eth1", "ip": "2.2.2.2"},
            ]
        }

    def test_creates_tunnel_between_different_firewalls(self) -> None:
        tunnels = build_ipsec_tunnels(self._make_two_firewall_tag_map(), "10.0.0.0/24", "vpn")
        self.assertEqual(len(tunnels), 1)
        tunnel = tunnels[0]
        self.assertEqual(tunnel["tag"], "wan")
        self.assertIn("interface1", tunnel)
        self.assertIn("interface2", tunnel)
        self.assertIn("secret", tunnel)
        self.assertIsInstance(tunnel["secret"], str)

    def test_skips_same_firewall_interfaces(self) -> None:
        tagstointerfaces = {
            "wan": [
                {"firewall": "fw1", "interface": "eth0", "ip": "1.1.1.1"},
                {"firewall": "fw1", "interface": "eth1", "ip": "1.1.1.2"},
            ]
        }
        tunnels = build_ipsec_tunnels(tagstointerfaces, "10.0.0.0/24", "vpn")
        self.assertEqual(len(tunnels), 0)

    def test_tunnel_ip_assignment(self) -> None:
        tunnels = build_ipsec_tunnels(self._make_two_firewall_tag_map(), "10.0.0.0/24", "vpn")
        self.assertIn("10.0.0.0", tunnels[0]["interface1"]["tunnel_ip"])
        self.assertIn("10.0.0.1", tunnels[0]["interface2"]["tunnel_ip"])

    def test_tunnel_names_are_set(self) -> None:
        tunnels = build_ipsec_tunnels(self._make_two_firewall_tag_map(), "10.0.0.0/24", "vpn")
        self.assertIn("tunnel_name", tunnels[0]["interface1"])
        self.assertIn("tunnel_name", tunnels[0]["interface2"])
        self.assertIn("vpn", tunnels[0]["interface1"]["tunnel_name"])

    def test_multiple_tags_creates_separate_tunnels(self) -> None:
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
        self.assertEqual(len(tunnels), 2)

    def test_ip_counter_advances_across_tunnels(self) -> None:
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
        ips = {tunnels[0]["interface1"]["tunnel_ip"], tunnels[0]["interface2"]["tunnel_ip"],
               tunnels[1]["interface1"]["tunnel_ip"], tunnels[1]["interface2"]["tunnel_ip"]}
        self.assertEqual(len(ips), 4)

    def test_empty_tags_returns_empty(self) -> None:
        tunnels = build_ipsec_tunnels({}, "10.0.0.0/24", "vpn")
        self.assertEqual(tunnels, [])


class BuildTunnelCallsTests(unittest.TestCase):
    def _make_tunnel(self, fw1="fw1", fw2="fw2"):
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

    def test_basic_structure(self) -> None:
        firewalls = [{"name": "fw1"}, {"name": "fw2"}]
        result = build_tunnel_calls([self._make_tunnel()], firewalls)
        self.assertIn("fw1", result)
        self.assertIn("fw2", result)
        self.assertEqual(len(result["fw1"]), 1)
        self.assertEqual(len(result["fw2"]), 1)

    def test_call_details_fw1(self) -> None:
        firewalls = [{"name": "fw1"}, {"name": "fw2"}]
        result = build_tunnel_calls([self._make_tunnel()], firewalls)
        call = result["fw1"][0]
        self.assertEqual(call["name"], "vpn_eth0-fw2-eth1")
        self.assertEqual(call["interface"], "eth0")
        self.assertEqual(call["remote_gateway"], "2.2.2.2")
        self.assertEqual(call["pre_shared_key"], "mysecret")
        self.assertEqual(call["tunnel_ip"], "10.0.0.0")
        self.assertEqual(call["remote_tunnel_ip"], "10.0.0.1")

    def test_call_details_fw2(self) -> None:
        firewalls = [{"name": "fw1"}, {"name": "fw2"}]
        result = build_tunnel_calls([self._make_tunnel()], firewalls)
        call = result["fw2"][0]
        self.assertEqual(call["name"], "vpn_eth1-fw1-eth0")
        self.assertEqual(call["interface"], "eth1")
        self.assertEqual(call["remote_gateway"], "1.1.1.1")
        self.assertEqual(call["tunnel_ip"], "10.0.0.1")
        self.assertEqual(call["remote_tunnel_ip"], "10.0.0.0")

    def test_empty_tunnels(self) -> None:
        firewalls = [{"name": "fw1"}, {"name": "fw2"}]
        result = build_tunnel_calls([], firewalls)
        self.assertEqual(result, {"fw1": [], "fw2": []})

    def test_multiple_tunnels_same_firewall(self) -> None:
        firewalls = [{"name": "fw1"}, {"name": "fw2"}]
        tunnels = [self._make_tunnel(), self._make_tunnel()]
        result = build_tunnel_calls(tunnels, firewalls)
        self.assertEqual(len(result["fw1"]), 2)
        self.assertEqual(len(result["fw2"]), 2)


class BuildTunnelIndexTests(unittest.TestCase):
    def test_basic_index(self) -> None:
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
        self.assertIn("fw1", index)
        self.assertIn("tunnel-a", index["fw1"])
        self.assertEqual(index["fw1"]["tunnel-a"]["interface"], "eth0")
        self.assertIn("tunnel-b", index["fw1"])
        self.assertIn("fw2", index)
        self.assertIn("tunnel-c", index["fw2"])

    def test_empty_firewalls(self) -> None:
        index = build_tunnel_index({})
        self.assertEqual(index, {})

    def test_all_tunnel_fields_preserved(self) -> None:
        tunnels_by_fw = {
            "fw1": [
                {"name": "t1", "interface": "eth0", "remote_gateway": "1.2.3.4", "pre_shared_key": "s"},
            ],
        }
        index = build_tunnel_index(tunnels_by_fw)
        self.assertEqual(index["fw1"]["t1"]["remote_gateway"], "1.2.3.4")
        self.assertEqual(index["fw1"]["t1"]["pre_shared_key"], "s")


if __name__ == "__main__":
    unittest.main()
