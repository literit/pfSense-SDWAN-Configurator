import pickle
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from src.ip import TunnelIpAllocator


@pytest.fixture
def network() -> str:
    return "10.0.0.0/30"


@pytest.fixture
def db(network: str) -> TunnelIpAllocator:
    return TunnelIpAllocator.init_db(network)


def test_alloc_is_idempotent_for_same_tunnel(db: TunnelIpAllocator) -> None:
    first = db.alloc("tunnel-a")
    second = db.alloc("tunnel-a")
    assert first == second


def test_allocates_in_order_and_raises_when_exhausted(db: TunnelIpAllocator) -> None:
    assert db.alloc("t1") == ("10.0.0.0", "10.0.0.1")
    assert db.alloc("t2") == ("10.0.0.2", "10.0.0.3")

    with pytest.raises(RuntimeError):
        db.alloc("t3")


def test_dealloc_returns_status_and_reuses_pair(db: TunnelIpAllocator) -> None:
    pair = db.alloc("t1")
    assert db.dealloc("t1") is True
    assert db.dealloc("t1") is False
    assert db.alloc("t2") == pair


def test_get_ip_and_find_tunnel_by_ip(db: TunnelIpAllocator) -> None:
    assert db.get_ip("missing") is None

    db.alloc("t1")
    assert db.get_ip("t1") == ("10.0.0.0", "10.0.0.1")
    assert db.find_tunnel_by_ip("10.0.0.0", "10.0.0.1") == "t1"
    assert db.find_tunnel_by_ip("10.0.0.1", "10.0.0.0") == "t1"
    assert db.find_tunnel_by_ip("10.0.0.2", "10.0.0.3") is None


def test_iter_allocations_returns_pair_to_tunnel_items(db: TunnelIpAllocator) -> None:
    db.alloc("t1")
    db.alloc("t2")

    items = set(db.iter_allocations())
    expected = {
        (("10.0.0.0", "10.0.0.1"), "t1"),
        (("10.0.0.2", "10.0.0.3"), "t2"),
    }
    assert items == expected


def test_iter_pairs_with_assignment_includes_unallocated_pairs(db: TunnelIpAllocator) -> None:
    db.alloc("t1")

    items = list(db.iter_pairs_with_assignment())
    assert items == [
        (("10.0.0.0", "10.0.0.1"), "t1"),
        (("10.0.0.2", "10.0.0.3"), None),
    ]


def test_save_and_import_db_round_trip(db: TunnelIpAllocator, network: str) -> None:
    db.alloc("t1")

    with TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "ipdb.pkl"
        db.save_db(str(db_path))

        loaded = TunnelIpAllocator.import_db(str(db_path))
        assert loaded.network_cidr == network
        assert loaded.get_ip("t1") == ("10.0.0.0", "10.0.0.1")
        assert loaded.alloc("t2") == ("10.0.0.2", "10.0.0.3")


def test_import_rejects_invalid_version(network: str) -> None:
    with TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "ipdb.pkl"
        db_path.write_bytes(
            pickle.dumps(
                {
                    "version": 999,
                    "network": network,
                    "allocations": {},
                }
            )
        )

        with pytest.raises(ValueError):
            TunnelIpAllocator.import_db(str(db_path))


def test_import_rejects_missing_network() -> None:
    with TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "ipdb.pkl"
        db_path.write_bytes(
            pickle.dumps(
                {
                    "version": TunnelIpAllocator.DB_VERSION,
                    "allocations": {},
                }
            )
        )

        with pytest.raises(ValueError):
            TunnelIpAllocator.import_db(str(db_path))


def test_import_rejects_non_dict_allocations(network: str) -> None:
    with TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "ipdb.pkl"
        db_path.write_bytes(
            pickle.dumps(
                {
                    "version": TunnelIpAllocator.DB_VERSION,
                    "network": network,
                    "allocations": [],
                }
            )
        )

        with pytest.raises(ValueError):
            TunnelIpAllocator.import_db(str(db_path))


def test_import_rejects_non_dict_allocation_entry(network: str) -> None:
    with TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "ipdb.pkl"
        db_path.write_bytes(
            pickle.dumps(
                {
                    "version": TunnelIpAllocator.DB_VERSION,
                    "network": network,
                    "allocations": {"t1": "bad"},
                }
            )
        )

        with pytest.raises(ValueError):
            TunnelIpAllocator.import_db(str(db_path))


def test_import_rejects_pair_outside_network(network: str) -> None:
    with TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "ipdb.pkl"
        db_path.write_bytes(
            pickle.dumps(
                {
                    "version": TunnelIpAllocator.DB_VERSION,
                    "network": network,
                    "allocations": {
                        "t1": {"ip1": "10.0.1.0", "ip2": "10.0.1.1"}
                    },
                }
            )
        )

        with pytest.raises(ValueError):
            TunnelIpAllocator.import_db(str(db_path))


def test_import_rejects_duplicate_pair(network: str) -> None:
    with TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "ipdb.pkl"
        db_path.write_bytes(
            pickle.dumps(
                {
                    "version": TunnelIpAllocator.DB_VERSION,
                    "network": network,
                    "allocations": {
                        "t1": {"ip1": "10.0.0.0", "ip2": "10.0.0.1"},
                        "t2": {"ip1": "10.0.0.1", "ip2": "10.0.0.0"},
                    },
                }
            )
        )

        with pytest.raises(ValueError):
            TunnelIpAllocator.import_db(str(db_path))
