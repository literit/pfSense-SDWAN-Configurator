"""Tunnel building and infrastructure module."""

import logging
from typing import Dict, List, Any, Optional

import ipcalc
import src.utils as utils
from src.ip import TunnelIpAllocator


def build_tag_interface_map(data: Dict[str, Any]) -> Dict[str, List[Dict[str, str]]]:
    """Builds a mapping of tags to the interfaces that use them.

    Args:
        data: The loaded configuration data from the YAML file.

    Returns:
        A dictionary mapping each tag to a list of interfaces that use it.
    """
    tagstointerfaces: Dict[str, List[Dict[str, str]]] = {}
    for firewall in data["firewalls"]:
        for interface in firewall["interfaces"]:
            for tag in interface["tags"]:
                if tag not in tagstointerfaces:
                    tagstointerfaces[tag] = []
                tagstointerfaces[tag].append({
                    "firewall": firewall["name"],
                    "interface": interface["name"],
                    "ip": interface["ip"]
                })

    logging.info(
        "Collected %d unique tags: %s",
        len(tagstointerfaces),
        ", ".join(sorted(tagstointerfaces.keys())),
    )
    
    for tag, interfaces in tagstointerfaces.items():
        logging.debug(f"Tag '{tag}' has {len(interfaces)} interfaces")
    
    return tagstointerfaces


def create_tunnel_name(
    hint_prefix: str,
    interface_name: str,
    remote_firewall: str,
    remote_interface: str
) -> str:
    """Creates a unique and descriptive name for an IPSec tunnel based on its details.

    Args:
        hint_prefix: A prefix to use in the tunnel name for identification.
        interface_name: The name of the local interface involved in the tunnel.
        remote_firewall: The name of the remote firewall on the other end of the tunnel.
        remote_interface: The name of the remote interface involved in the tunnel.
    
    Returns:
        A string representing the generated tunnel name.
    """
    return f"{hint_prefix}_{interface_name}_{remote_firewall}_{remote_interface}"


# I could probably merge this and the next function into one. I 
def build_ipsec_tunnels(
    tagstointerfaces: Dict[str, List[Dict[str, str]]], 
    tunnels_network: str, 
    hint_prefix: str,
    ip_allocator: Optional[TunnelIpAllocator] = None,
) -> List[Dict[str, Any]]:
    """Builds a list of IPSec tunnels based on the mapping of tags to interfaces.
    
    For each tag, it creates tunnels between all pairs of interfaces that share that tag,
    ensuring that tunnels are only created between interfaces on different firewalls.
    Each tunnel is assigned a unique name and IP address from the specified tunnel network.
    
    Args:
        tagstointerfaces: A dictionary mapping each tag to a list of interfaces that use it.
        tunnels_network: The network range to use for assigning tunnel IP addresses.
        hint_prefix: A prefix to use in the tunnel names for identification.
        
    Returns:
        A list of dictionaries, each representing an IPSec tunnel with its associated
        interfaces and configuration details.
    """
    ipsectunnels = []
    allocator = ip_allocator or TunnelIpAllocator.init_db(tunnels_network)
    
    logging.info(f"Building IPSec tunnels from network {tunnels_network}")
    
    for tag, interfaces in tagstointerfaces.items():
        for i in range(len(interfaces)):
            for j in range(i + 1, len(interfaces)):
                if interfaces[i]["firewall"] != interfaces[j]["firewall"]:
                    endpoint1 = interfaces[i]
                    endpoint2 = interfaces[j]

                    tunnel_id = "|".join(
                        sorted(
                            [
                                f"{tag}:{endpoint1['firewall']}:{endpoint1['interface']}",
                                f"{tag}:{endpoint2['firewall']}:{endpoint2['interface']}",
                            ]
                        )
                    )
                    tunnel_ip1, tunnel_ip2 = allocator.alloc(tunnel_id)

                    interface1 = dict(endpoint1)
                    interface1["tunnel_name"] = create_tunnel_name(
                        hint_prefix,
                        endpoint1["interface"],
                        endpoint2["firewall"],
                        endpoint2["interface"]
                    )
                    interface1["tunnel_ip"] = tunnel_ip1

                    interface2 = dict(endpoint2)
                    interface2["tunnel_name"] = create_tunnel_name(
                        hint_prefix,
                        endpoint2["interface"],
                        endpoint1["firewall"],
                        endpoint1["interface"]
                    )
                    interface2["tunnel_ip"] = tunnel_ip2

                    ipsectunnels.append({
                        "tag": tag,
                        "interface1": interface1,
                        "interface2": interface2,
                        "secret": utils.generate_random_password(24),
                    })
    
    logging.info(f"Created {len(ipsectunnels)} IPSec tunnel configurations")
    return ipsectunnels


def build_tunnel_calls(
    ipsectunnels: List[Dict[str, Any]], 
    firewalls: List[Dict[str, Any]]
) -> Dict[str, List[Dict[str, str]]]:
    """Organizes the IPSec tunnels by firewall to simplify API calls.
    
    For each tunnel, it creates two call objects (one for each firewall) with the
    necessary details for configuring the tunnel on that firewall. The resulting
    structure is a dictionary mapping each firewall name to a list of tunnel call
    objects that need to be applied to that firewall.
    
    Args:
        ipsectunnels: A list of dictionaries, each representing an IPSec tunnel.
        firewalls: A list of firewall configurations from the loaded YAML data.
        
    Returns:
        A dictionary mapping each firewall name to a list of tunnel call objects.
    """
    ipsectunnelsbyfirewall = {firewall["name"]: [] for firewall in firewalls}
    
    for tunnel in ipsectunnels:
        firewall1 = tunnel["interface1"]["firewall"]
        firewall2 = tunnel["interface2"]["firewall"]

        call1 = {
            "name": tunnel["interface1"]["tunnel_name"],
            "interface": tunnel["interface1"]["interface"],
            "remote_gateway": tunnel["interface2"]["ip"],
            "pre_shared_key": tunnel["secret"],
            "tunnel_ip": tunnel["interface1"]["tunnel_ip"],
            "remote_tunnel_ip": tunnel["interface2"]["tunnel_ip"]
        }
        call2 = {
            "name": tunnel["interface2"]["tunnel_name"],
            "interface": tunnel["interface2"]["interface"],
            "remote_gateway": tunnel["interface1"]["ip"],
            "pre_shared_key": tunnel["secret"],
            "tunnel_ip": tunnel["interface2"]["tunnel_ip"],
            "remote_tunnel_ip": tunnel["interface1"]["tunnel_ip"]
        }

        ipsectunnelsbyfirewall[firewall1].append(call1)
        ipsectunnelsbyfirewall[firewall2].append(call2)
    
    for fw, tunnels in ipsectunnelsbyfirewall.items():
        logging.debug(f"Firewall '{fw}' has {len(tunnels)} tunnels")
    
    return ipsectunnelsbyfirewall



def build_tunnel_index(
    ipsectunnelsbyfirewall: Dict[str, List[Dict[str, str]]]
) -> Dict[str, Dict[str, Dict[str, str]]]:
    """Builds an index for quick lookup of tunnels by firewall name and description.

    Args:
        ipsectunnelsbyfirewall: Mapping of firewall names to tunnel call details.

    Returns:
        A dictionary mapping each firewall name to a dictionary of tunnel names
        to tunnel details.
    """
    return {
        fw: {t["name"]: t for t in tunnels}
        for fw, tunnels in ipsectunnelsbyfirewall.items()
    }
