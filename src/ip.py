"""IP allocation database for tunnel IP-pairs."""

from __future__ import annotations

from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple
import pickle


IPPair = Tuple[str, str]


class TunnelIpAllocator:
    """Keeps tunnel-id <-> IP-pair allocations and supports persistence."""

    DB_VERSION = 1

    def __init__(self, network_cidr: str):
        self.network_cidr = network_cidr
        self.network = ip_network(network_cidr, strict=False)

        self._all_pairs: List[IPPair] = self._build_all_pairs()
        self._allocations: Dict[str, IPPair] = {}
        self._ip_to_tunnel: Dict[IPPair, str] = {}

    @classmethod
    def init_db(cls, network_cidr: str) -> "TunnelIpAllocator":
        """Initialize a new in-memory DB for a tunnel network."""
        return cls(network_cidr)

    @classmethod
    def import_db(cls, file_path: str) -> "TunnelIpAllocator":
        """Load DB from Pickle file and recreate in-memory indexes."""
        path = Path(file_path)
        with path.open("rb") as file:
            data = pickle.load(file)

        if not isinstance(data, dict):
            raise ValueError("DB payload must be a dictionary")

        if data.get("version") != cls.DB_VERSION:
            raise ValueError(
                f"Unsupported DB version: {data.get('version')}. "
                f"Expected {cls.DB_VERSION}."
            )

        network_cidr = data.get("network")
        if not isinstance(network_cidr, str):
            raise ValueError("DB is missing a valid 'network' value")

        allocator = cls(network_cidr)
        allocations = data.get("allocations", {})

        if not isinstance(allocations, dict):
            raise ValueError("DB 'allocations' must be a dictionary")

        for tunnel_id, value in allocations.items():
            if not isinstance(value, dict):
                raise ValueError(f"Invalid allocation entry for tunnel '{tunnel_id}'")

            ip_pair = allocator._normalize_pair(value.get("ip1"), value.get("ip2"))

            if ip_pair not in allocator._all_pairs:
                raise ValueError(
                    f"Allocation {ip_pair} for tunnel '{tunnel_id}' "
                    f"is not inside network {allocator.network_cidr}"
                )

            if ip_pair in allocator._ip_to_tunnel:
                existing = allocator._ip_to_tunnel[ip_pair]
                raise ValueError(
                    f"Duplicate IP pair {ip_pair} in DB for tunnels "
                    f"'{existing}' and '{tunnel_id}'"
                )

            allocator._allocations[tunnel_id] = ip_pair
            allocator._ip_to_tunnel[ip_pair] = tunnel_id

        return allocator

    def save_db(self, file_path: str) -> None:
        """Persist DB to a Pickle file."""
        path = Path(file_path)
        serializable = {
            tunnel_id: {"ip1": pair[0], "ip2": pair[1]}
            for tunnel_id, pair in self._allocations.items()
        }
        data = {
            "version": self.DB_VERSION,
            "network": self.network_cidr,
            "allocations": serializable,
        }
        with path.open("wb") as file:
            pickle.dump(data, file)

    def alloc(self, tunnel_id: str) -> IPPair:
        """Allocate the next available IP-pair for a tunnel id.

        Allocation is idempotent: if tunnel_id is already allocated,
        the existing pair is returned.
        """
        if tunnel_id in self._allocations:
            return self._allocations[tunnel_id]

        for pair in self._all_pairs:
            if pair not in self._ip_to_tunnel:
                self._allocations[tunnel_id] = pair
                self._ip_to_tunnel[pair] = tunnel_id
                return pair

        raise RuntimeError(f"No free IP pairs left in network {self.network_cidr}")

    def dealloc(self, tunnel_id: str) -> bool:
        """Remove an allocation by tunnel id.

        Returns True when an allocation existed and was removed.
        """
        pair = self._allocations.pop(tunnel_id, None)
        if pair is None:
            return False

        self._ip_to_tunnel.pop(pair, None)
        return True

    def get_ip(self, tunnel_id: str) -> Optional[IPPair]:
        """Get allocated IP-pair by tunnel id."""
        return self._allocations.get(tunnel_id)

    def find_tunnel_by_ip(self, ip1: str, ip2: str) -> Optional[str]:
        """Get tunnel id by IP-pair."""
        pair = self._normalize_pair(ip1, ip2)
        return self._ip_to_tunnel.get(pair)

    def iter_allocations(self) -> Iterator[Tuple[IPPair, str]]:
        """Iterate over currently allocated pairs as ((ip1, ip2), tunnel_id)."""
        for pair, tunnel_id in self._ip_to_tunnel.items():
            yield pair, tunnel_id

    def iter_pairs_with_assignment(self) -> Iterator[Tuple[IPPair, Optional[str]]]:
        """Iterate over every pair in network with optional assigned tunnel id."""
        for pair in self._all_pairs:
            yield pair, self._ip_to_tunnel.get(pair)

    def _build_all_pairs(self) -> List[IPPair]:
        """Build all possible sequential IP-pairs in the configured network."""
        start = int(self.network.network_address)
        end = int(self.network.broadcast_address)

        pairs: List[IPPair] = []
        current = start
        while current + 1 <= end:
            ip1 = str(ip_address(current))
            ip2 = str(ip_address(current + 1))
            pairs.append((ip1, ip2))
            current += 2
        return pairs

    def _normalize_pair(self, ip1: object, ip2: object) -> IPPair:
        """Validate and normalize IP pair ordering."""
        if not isinstance(ip1, str) or not isinstance(ip2, str):
            raise ValueError("IP pair must contain string addresses")

        p1 = ip_address(ip1)
        p2 = ip_address(ip2)

        if p1.version != p2.version:
            raise ValueError("IP pair must use the same address family")

        if int(p1) > int(p2):
            p1, p2 = p2, p1

        return str(p1), str(p2)