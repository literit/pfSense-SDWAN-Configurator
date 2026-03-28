"""IPSec phase configuration module."""

import logging
from typing import Dict, Any, Mapping, Tuple, TypedDict

import ipcalc
from pfapi.models import (
    Phase1, Phase1Encryption, Phase2, Phase2LocalId, Phase2RemoteId,
    EncryptionAlgorithm
)


DEFAULT_IPSEC_SETTINGS = {
    "ike": "ikev2",
    "p1_encryption": "aes",
    "p1_encryption_bits": "128",
    "p1_hash": "sha256",
    "p1_group": "14",
    "p2_encryption": "aes",
    "p2_encryption_bits": "128",
    "p2_hash": "sha256",
    "p2_group": "14",
}

SUPPORTED_IKE = {"ikev1", "ikev2"}
SUPPORTED_PHASE1_ENCRYPTION = {"aes", "aes128gcm", "aes256gcm", "chacha20poly1305"}
SUPPORTED_PHASE2_ENCRYPTION = {"aes", "aes128gcm", "aes256gcm", "chacha20poly1305"}
SUPPORTED_PHASE1_HASH = {"", "sha1", "sha256", "sha384", "sha512"}
SUPPORTED_PHASE2_HASH = {"", "sha1", "sha256", "sha384", "sha512"}


class IpsecConfig(TypedDict, total=False):
    """IPSec settings accepted from YAML."""

    ike: str
    p1_encryption: str
    p1_encryption_bits: str
    p1_hash: str | None
    p1_group: str
    p2_encryption: str
    p2_encryption_bits: str
    p2_hash: str | None
    p2_group: str


def _normalize_ipsec_settings(ipsec_config: Mapping[str, Any] | None) -> Dict[str, str]:
    """Normalizes user-supplied IPSec settings with defaults."""
    merged: Dict[str, Any] = {**DEFAULT_IPSEC_SETTINGS, **(ipsec_config or {})}

    normalized: Dict[str, str] = {}
    for key, value in merged.items():
        if value is None:
            normalized[key] = ""
            continue
        normalized[key] = str(value)

    return normalized


def _validate_positive_integer(value: str, key: str) -> None:
    try:
        parsed = int(value)
    except ValueError as err:
        raise ValueError(f"Invalid IPSec setting '{key}': '{value}' is not an integer") from err

    if parsed <= 0:
        raise ValueError(f"Invalid IPSec setting '{key}': '{value}' must be greater than 0")


def _validate_ipsec_settings(settings: Dict[str, str]) -> None:
    """Validates normalized IPSec settings."""
    if settings["ike"] not in SUPPORTED_IKE:
        raise ValueError(
            f"Invalid IPSec setting 'ike': '{settings['ike']}'. "
            f"Supported values: {', '.join(sorted(SUPPORTED_IKE))}"
        )

    if settings["p1_encryption"] not in SUPPORTED_PHASE1_ENCRYPTION:
        raise ValueError(
            f"Invalid IPSec setting 'p1_encryption': '{settings['p1_encryption']}'. "
            f"Supported values: {', '.join(sorted(SUPPORTED_PHASE1_ENCRYPTION))}"
        )

    if settings["p2_encryption"] not in SUPPORTED_PHASE2_ENCRYPTION:
        raise ValueError(
            f"Invalid IPSec setting 'p2_encryption': '{settings['p2_encryption']}'. "
            f"Supported values: {', '.join(sorted(SUPPORTED_PHASE2_ENCRYPTION))}"
        )

    if settings["p1_hash"] not in SUPPORTED_PHASE1_HASH:
        raise ValueError(
            f"Invalid IPSec setting 'p1_hash': '{settings['p1_hash']}'. "
            f"Supported values: {', '.join(sorted(SUPPORTED_PHASE1_HASH))}"
        )

    if settings["p2_hash"] not in SUPPORTED_PHASE2_HASH:
        raise ValueError(
            f"Invalid IPSec setting 'p2_hash': '{settings['p2_hash']}'. "
            f"Supported values: {', '.join(sorted(SUPPORTED_PHASE2_HASH))}"
        )

    _validate_positive_integer(settings["p1_group"], "p1_group")
    _validate_positive_integer(settings["p2_group"], "p2_group")
    _validate_positive_integer(settings["p1_encryption_bits"], "p1_encryption_bits")
    _validate_positive_integer(settings["p2_encryption_bits"], "p2_encryption_bits")


def make_ipsec_phases(
    tunnel: Dict[str, str],
    ipsec_config: Mapping[str, Any] | None,
) -> Tuple[Phase1, Phase2]:
    """Creates Phase 1 and Phase 2 configuration objects for a given tunnel.
    
    The configuration is based on consistent defaults for all tunnels, with specific
    details filled in from the tunnel information. This includes settings for
    authentication, encryption, lifetime, and other parameters necessary for
    establishing the IPSec tunnel.
    
    Args:
        tunnel: A dictionary containing the tunnel details.
        ipsec_config: IPSec config values from YAML.
        
    Returns:
        A tuple of (Phase1, Phase2) objects configured for the tunnel.
    """
    settings = _normalize_ipsec_settings(ipsec_config)
    _validate_ipsec_settings(settings)

    phase1 = Phase1(iketype=settings["ike"])
    phase1.disabled = False
    phase1.descr = tunnel["name"]
    phase1.interface = tunnel["interface"]
    phase1.remote_gateway = tunnel["remote_gateway"]
    phase1.pre_shared_key = tunnel["pre_shared_key"]

    phase1.authentication_method = "pre_shared_key"
    phase1.protocol = "inet"
    phase1.myid_type = "myaddress"
    phase1.peerid_type = "peeraddress"

    phase1.lifetime = 28800  # 8 hours
    phase1.nat_traversal = "on"
    phase1.mobike = "off"
    phase1.gw_duplicates = True
    phase1.prfselect_enable = False

    phase1.dpd_delay = 10
    phase1.dpd_maxfail = 5

    phase1_encryption_algorithm = {"name": settings["p1_encryption"]}
    if settings["p1_encryption_bits"]:
        phase1_encryption_algorithm["keylen"] = settings["p1_encryption_bits"]

    phase1_item = {
        "dhgroup": settings["p1_group"],
        "encryption_algorithm": phase1_encryption_algorithm,
    }
    if settings["p1_hash"]:
        phase1_item["hash_algorithm"] = settings["p1_hash"]

    encryption_dict = {
        'item': [{
            **phase1_item
        }]
    }
    phase1.encryption = Phase1Encryption.from_dict(encryption_dict)
    
    phase2 = Phase2()
    # ikeid links phase 2 to phase 1, but it is not known until phase 1 is applied
    # and the API response is received with the assigned ike_id.
    # This will be updated in the tunnel index after applying phase 1.
    phase2.mode = "vti"
    localid_dict = {
        'type': 'network',
        'address': ipcalc.IP(tunnel["tunnel_ip"]).dq,
        'netbits': "31"
    }
    phase2.localid = Phase2LocalId.from_dict(localid_dict)
    remoteid_dict = {
        'type': 'network',
        'address': ipcalc.IP(tunnel["remote_tunnel_ip"]).dq,
        'netbits': "31"
    }
    phase2.remoteid = Phase2RemoteId.from_dict(remoteid_dict)
    phase2.protocol = "esp"
    phase2_encryption_algorithm = {"name": settings["p2_encryption"]}
    if settings["p2_encryption_bits"]:
        phase2_encryption_algorithm["keylen"] = settings["p2_encryption_bits"]

    phase2.encryption_algorithm_option = [
        EncryptionAlgorithm.from_dict(phase2_encryption_algorithm)
    ]
    phase2.hash_algorithm_option = [settings["p2_hash"]] if settings["p2_hash"] or settings["p2_hash"] != "" else []
    phase2.pfsgroup = settings["p2_group"]
    phase2.lifetime = 3600  # 1 hour
    phase2.rekey_time = 0
    phase2.rand_time = 0
    phase2.pinghost = ""
    phase2.keepalive = False
    phase2.mobile = False
    phase2.disabled = False
    phase2.descr = tunnel["name"]
    
    return phase1, phase2


def build_ipsec_calls(
    ipsectunnelsbyfirewall: Dict[str, Any],
    ipsec_config: Mapping[str, Any],
    tunnel_index: Dict[str, Dict[str, Any]]
) -> Tuple[Dict[str, Any], Dict[str, Dict[str, Any]]]:
    """Builds Phase 1 and Phase 2 configuration objects for all tunnels.
    
    Args:
        ipsectunnelsbyfirewall: Mapping of firewall names to tunnel call details.
        ipsec_config: IPSec settings from YAML.
        tunnel_index: Mapping of firewall names to tunnel details for quick lookup.
        
    Returns:
        A tuple of (ipsectunnelcalls, tunnel_index) where:
        - ipsectunnelcalls: Mapping of firewall names to Phase 1 configuration objects
        - tunnel_index: Updated tunnel index including Phase 2 configuration objects
    """
    settings = _normalize_ipsec_settings(ipsec_config)
    _validate_ipsec_settings(settings)

    # Prepare Phase 1 objects per firewall.
    ipsectunnelcalls = {firewall: [] for firewall in ipsectunnelsbyfirewall}
    
    for firewall, tunnels in ipsectunnelsbyfirewall.items():
        for tunnel in tunnels:
            phase1, phase2 = make_ipsec_phases(tunnel, settings)
            ipsectunnelcalls[firewall].append(phase1)
            tunnel_index[firewall][tunnel["name"]]["phase2"] = phase2
            tunnel_index[firewall][tunnel["name"]]["tunnel_id"] = tunnel.get("tunnel_id", "")
    
    logging.info("Built IPSec Phase 1 and Phase 2 configurations")
    return ipsectunnelcalls, tunnel_index
