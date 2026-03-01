import sys
import unittest
from unittest.mock import MagicMock

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


class MakeIpsecPhasesTests(unittest.TestCase):
    def _make_tunnel(self):
        return {
            "name": "vpn_eth0-fw2-eth1",
            "interface": "eth0",
            "remote_gateway": "2.2.2.2",
            "pre_shared_key": "mysecret",
            "tunnel_ip": "10.0.0.0",
            "remote_tunnel_ip": "10.0.0.1",
        }

    def test_returns_tuple_of_two(self) -> None:
        result = make_ipsec_phases(self._make_tunnel(), "ikev2")
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

    def test_phase1_key_attributes(self) -> None:
        tunnel = self._make_tunnel()
        phase1, _ = make_ipsec_phases(tunnel, "ikev2")
        self.assertEqual(phase1.descr, tunnel["name"])
        self.assertEqual(phase1.interface, tunnel["interface"])
        self.assertEqual(phase1.remote_gateway, tunnel["remote_gateway"])
        self.assertEqual(phase1.pre_shared_key, tunnel["pre_shared_key"])

    def test_phase1_security_settings(self) -> None:
        phase1, _ = make_ipsec_phases(self._make_tunnel(), "ikev2")
        self.assertFalse(phase1.disabled)
        self.assertEqual(phase1.authentication_method, "pre_shared_key")
        self.assertEqual(phase1.lifetime, 28800)
        self.assertEqual(phase1.nat_traversal, "on")
        self.assertEqual(phase1.mobike, "off")
        self.assertEqual(phase1.dpd_delay, 10)
        self.assertEqual(phase1.dpd_maxfail, 5)

    def test_phase2_key_attributes(self) -> None:
        tunnel = self._make_tunnel()
        _, phase2 = make_ipsec_phases(tunnel, "ikev2")
        self.assertEqual(phase2.mode, "vti")
        self.assertEqual(phase2.protocol, "esp")
        self.assertEqual(phase2.descr, tunnel["name"])
        self.assertFalse(phase2.disabled)

    def test_phase2_lifetime_and_rekey(self) -> None:
        _, phase2 = make_ipsec_phases(self._make_tunnel(), "ikev2")
        self.assertEqual(phase2.lifetime, 3600)
        self.assertEqual(phase2.rekey_time, 0)
        self.assertEqual(phase2.rand_time, 0)
        self.assertFalse(phase2.keepalive)
        self.assertFalse(phase2.mobile)

    def test_different_ike_versions(self) -> None:
        for ike_version in ["ikev1", "ikev2"]:
            with self.subTest(ike_version=ike_version):
                result = make_ipsec_phases(self._make_tunnel(), ike_version)
                self.assertEqual(len(result), 2)


class BuildIpsecCallsTests(unittest.TestCase):
    def _make_tunnels_by_firewall(self):
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

    def _tunnel_index(self):
        return {
            "fw1": {"tunnel-a": {}},
            "fw2": {"tunnel-b": {}},
        }

    def test_returns_calls_per_firewall(self) -> None:
        calls, _ = build_ipsec_calls(self._make_tunnels_by_firewall(), "ikev2", self._tunnel_index())
        self.assertIn("fw1", calls)
        self.assertIn("fw2", calls)
        self.assertEqual(len(calls["fw1"]), 1)
        self.assertEqual(len(calls["fw2"]), 1)

    def test_tunnel_index_updated_with_phase2(self) -> None:
        _, index = build_ipsec_calls(self._make_tunnels_by_firewall(), "ikev2", self._tunnel_index())
        self.assertIn("phase2", index["fw1"]["tunnel-a"])
        self.assertIn("phase2", index["fw2"]["tunnel-b"])

    def test_empty_firewalls(self) -> None:
        calls, index = build_ipsec_calls({}, "ikev2", {})
        self.assertEqual(calls, {})
        self.assertEqual(index, {})

    def test_phase1_objects_are_in_calls_list(self) -> None:
        calls, _ = build_ipsec_calls(self._make_tunnels_by_firewall(), "ikev2", self._tunnel_index())
        # Each entry in the calls list should be a Phase1 object (MagicMock instance here)
        self.assertIsNotNone(calls["fw1"][0])
        self.assertIsNotNone(calls["fw2"][0])


if __name__ == "__main__":
    unittest.main()
