"""Tunnel building and infrastructure module."""

import logging
from typing import Dict, List, Set, Any

import ipcalc
import src.utils as utils


def collect_tags(data: Dict[str, Any]) -> Set[str]:
    """Collects all unique tags from the interfaces defined in the configuration data.
    
    Args:
        data: The loaded configuration data from the YAML file.
        
    Returns:
        A set of unique tags found across all interfaces in the configuration.
    """
    tags = set()
    for firewall in data["firewalls"]:
        for interface in firewall["interfaces"]:
            tags.update(interface["tags"])
    
    logging.info(f"Collected {len(tags)} unique tags: {', '.join(sorted(tags))}")
    return tags


def build_tag_interface_map(data: Dict[str, Any], tags: Set[str]) -> Dict[str, List[Dict[str, str]]]:
    """Builds a mapping of tags to the interfaces that use them.
    
    Args:
        data: The loaded configuration data from the YAML file.
        tags: A set of unique tags found across all interfaces in the configuration.
        
    Returns:
        A dictionary mapping each tag to a list of interfaces that use it.
    """
    tagstointerfaces = {tag: [] for tag in tags}
    for firewall in data["firewalls"]:
        for interface in firewall["interfaces"]:
            for tag in tags:
                if tag in interface["tags"]:
                    tagstointerfaces[tag].append({
                        "firewall": firewall["name"],
                        "interface": interface["name"],
                        "ip": interface["ip"]
                    })
    
    for tag, interfaces in tagstointerfaces.items():
        logging.debug(f"Tag '{tag}' has {len(interfaces)} interfaces")
    
    return tagstointerfaces


def build_ipsec_tunnels(
    tagstointerfaces: Dict[str, List[Dict[str, str]]], 
    tunnels_network: str, 
    hint_prefix: str
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
    ipcounter = 0
    
    logging.info(f"Building IPSec tunnels from network {tunnels_network}")
    
    for tag, interfaces in tagstointerfaces.items():
        for i in range(len(interfaces)):
            for j in range(i + 1, len(interfaces)):
                if interfaces[i]["firewall"] != interfaces[j]["firewall"]:
                    interface1 = dict(interfaces[i])
                    interface1["tunnel_name"] = (
                        f"{hint_prefix}_{interfaces[i]['interface']}"
                        f"-{interfaces[j]['firewall']}-{interfaces[j]['interface']}"
                    )
                    interface1["tunnel_ip"] = str(ipcalc.Network(tunnels_network) + ipcounter)

                    interface2 = dict(interfaces[j])
                    interface2["tunnel_name"] = (
                        f"{hint_prefix}_{interfaces[j]['interface']}"
                        f"-{interfaces[i]['firewall']}-{interfaces[i]['interface']}"
                    )
                    interface2["tunnel_ip"] = str(ipcalc.Network(tunnels_network) + ipcounter + 1)  # type: ignore
                    ipcounter += 2

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
