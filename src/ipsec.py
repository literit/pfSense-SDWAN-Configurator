"""IPSec phase configuration module."""

import logging
from typing import Dict, Any, Tuple

import ipcalc
from pfapi.models import (
    Phase1, Phase1Encryption, Phase2, Phase2LocalId, Phase2RemoteId,
    EncryptionAlgorithm
)


def make_ipsec_phases(tunnel: Dict[str, str], ike_version: str) -> Tuple[Phase1, Phase2]:
    """Creates Phase 1 and Phase 2 configuration objects for a given tunnel.
    
    The configuration is based on consistent defaults for all tunnels, with specific
    details filled in from the tunnel information. This includes settings for
    authentication, encryption, lifetime, and other parameters necessary for
    establishing the IPSec tunnel.
    
    Args:
        tunnel: A dictionary containing the tunnel details.
        ike_version: The IKE version to use (e.g., "ikev2").
        
    Returns:
        A tuple of (Phase1, Phase2) objects configured for the tunnel.
    """
    phase1 = Phase1(iketype=ike_version)
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

    encryption_dict = {
        'item': [{
            'dhgroup': '14',
            'encryption_algorithm': {'keylen': '128', 'name': 'aes'},
            'hash_algorithm': 'sha256'
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
    phase2.encryption_algorithm_option = [
        EncryptionAlgorithm.from_dict({"name": "aes", "keylen": "128"}),
        EncryptionAlgorithm.from_dict({"name": "aes128gcm", "keylen": "128"})
    ]
    phase2.hash_algorithm_option = ["hmac_sha256"]
    phase2.pfsgroup = "14"
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
    ike_version: str,
    tunnel_index: Dict[str, Dict[str, Any]]
) -> Tuple[Dict[str, Any], Dict[str, Dict[str, Any]]]:
    """Builds Phase 1 and Phase 2 configuration objects for all tunnels.
    
    Args:
        ipsectunnelsbyfirewall: Mapping of firewall names to tunnel call details.
        ike_version: The IKE version to use for all Phase 1 configurations.
        tunnel_index: Mapping of firewall names to tunnel details for quick lookup.
        
    Returns:
        A tuple of (ipsectunnelcalls, tunnel_index) where:
        - ipsectunnelcalls: Mapping of firewall names to Phase 1 configuration objects
        - tunnel_index: Updated tunnel index including Phase 2 configuration objects
    """
    # Prepare Phase 1 objects per firewall.
    ipsectunnelcalls = {firewall: [] for firewall in ipsectunnelsbyfirewall}
    
    for firewall, tunnels in ipsectunnelsbyfirewall.items():
        for tunnel in tunnels:
            phase1, phase2 = make_ipsec_phases(tunnel, ike_version)
            ipsectunnelcalls[firewall].append(phase1)
            tunnel_index[firewall][tunnel["name"]]["phase2"] = phase2
    
    logging.info("Built IPSec Phase 1 and Phase 2 configurations")
    return ipsectunnelcalls, tunnel_index
