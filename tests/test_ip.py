import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from src.ip import TunnelIpAllocator


class TunnelIpAllocatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.network = "10.0.0.0/30"
        self.db = TunnelIpAllocator.init_db(self.network)

    def test_alloc_is_idempotent_for_same_tunnel(self) -> None:
        first = self.db.alloc("tunnel-a")
        second = self.db.alloc("tunnel-a")
        self.assertEqual(first, second)

    def test_allocates_in_order_and_raises_when_exhausted(self) -> None:
        self.assertEqual(self.db.alloc("t1"), ("10.0.0.0", "10.0.0.1"))
        self.assertEqual(self.db.alloc("t2"), ("10.0.0.2", "10.0.0.3"))

        with self.assertRaises(RuntimeError):
            self.db.alloc("t3")

    def test_dealloc_returns_status_and_reuses_pair(self) -> None:
        pair = self.db.alloc("t1")
        self.assertTrue(self.db.dealloc("t1"))
        self.assertFalse(self.db.dealloc("t1"))
        self.assertEqual(self.db.alloc("t2"), pair)

    def test_get_ip_and_find_tunnel_by_ip(self) -> None:
        self.assertIsNone(self.db.get_ip("missing"))

        self.db.alloc("t1")
        self.assertEqual(self.db.get_ip("t1"), ("10.0.0.0", "10.0.0.1"))
        self.assertEqual(self.db.find_tunnel_by_ip("10.0.0.0", "10.0.0.1"), "t1")
        self.assertEqual(self.db.find_tunnel_by_ip("10.0.0.1", "10.0.0.0"), "t1")
        self.assertIsNone(self.db.find_tunnel_by_ip("10.0.0.2", "10.0.0.3"))

    def test_iter_allocations_returns_pair_to_tunnel_items(self) -> None:
        self.db.alloc("t1")
        self.db.alloc("t2")

        items = set(self.db.iter_allocations())
        expected = {
            (("10.0.0.0", "10.0.0.1"), "t1"),
            (("10.0.0.2", "10.0.0.3"), "t2"),
        }
        self.assertEqual(items, expected)

    def test_iter_pairs_with_assignment_includes_unallocated_pairs(self) -> None:
        self.db.alloc("t1")

        items = list(self.db.iter_pairs_with_assignment())
        self.assertEqual(
            items,
            [
                (("10.0.0.0", "10.0.0.1"), "t1"),
                (("10.0.0.2", "10.0.0.3"), None),
            ],
        )

    def test_save_and_import_db_round_trip(self) -> None:
        self.db.alloc("t1")

        with TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "ipdb.json"
            self.db.save_db(str(db_path))

            loaded = TunnelIpAllocator.import_db(str(db_path))
            self.assertEqual(loaded.network_cidr, self.network)
            self.assertEqual(loaded.get_ip("t1"), ("10.0.0.0", "10.0.0.1"))
            self.assertEqual(loaded.alloc("t2"), ("10.0.0.2", "10.0.0.3"))

    def test_import_rejects_invalid_version(self) -> None:
        with TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "ipdb.json"
            db_path.write_text(
                json.dumps(
                    {
                        "version": 999,
                        "network": self.network,
                        "allocations": {},
                    }
                )
            )

            with self.assertRaises(ValueError):
                TunnelIpAllocator.import_db(str(db_path))

    def test_import_rejects_missing_network(self) -> None:
        with TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "ipdb.json"
            db_path.write_text(
                json.dumps(
                    {
                        "version": TunnelIpAllocator.DB_VERSION,
                        "allocations": {},
                    }
                )
            )

            with self.assertRaises(ValueError):
                TunnelIpAllocator.import_db(str(db_path))

    def test_import_rejects_non_dict_allocations(self) -> None:
        with TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "ipdb.json"
            db_path.write_text(
                json.dumps(
                    {
                        "version": TunnelIpAllocator.DB_VERSION,
                        "network": self.network,
                        "allocations": [],
                    }
                )
            )

            with self.assertRaises(ValueError):
                TunnelIpAllocator.import_db(str(db_path))

    def test_import_rejects_non_dict_allocation_entry(self) -> None:
        with TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "ipdb.json"
            db_path.write_text(
                json.dumps(
                    {
                        "version": TunnelIpAllocator.DB_VERSION,
                        "network": self.network,
                        "allocations": {"t1": "bad"},
                    }
                )
            )

            with self.assertRaises(ValueError):
                TunnelIpAllocator.import_db(str(db_path))

    def test_import_rejects_pair_outside_network(self) -> None:
        with TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "ipdb.json"
            db_path.write_text(
                json.dumps(
                    {
                        "version": TunnelIpAllocator.DB_VERSION,
                        "network": self.network,
                        "allocations": {
                            "t1": {"ip1": "10.0.1.0", "ip2": "10.0.1.1"}
                        },
                    }
                )
            )

            with self.assertRaises(ValueError):
                TunnelIpAllocator.import_db(str(db_path))

    def test_import_rejects_duplicate_pair(self) -> None:
        with TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "ipdb.json"
            db_path.write_text(
                json.dumps(
                    {
                        "version": TunnelIpAllocator.DB_VERSION,
                        "network": self.network,
                        "allocations": {
                            "t1": {"ip1": "10.0.0.0", "ip2": "10.0.0.1"},
                            "t2": {"ip1": "10.0.0.1", "ip2": "10.0.0.0"},
                        },
                    }
                )
            )

            with self.assertRaises(ValueError):
                TunnelIpAllocator.import_db(str(db_path))


if __name__ == "__main__":
    unittest.main()
