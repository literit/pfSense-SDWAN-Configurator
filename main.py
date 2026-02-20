# Import libraries for configuration, API interaction, and network calculations
import yaml
import argparse
import logging
import src.utils as utils
from src.helper_funcs import *
import ipcalc
import sys
from typing import Dict, List, Set, Any, Tuple
from pprint import pprint

# Import pfSense API models and methods for IPSec and device management
from pfapi.models import *
from pfapi.api.vpn import set_ip_sec_phase_1, set_ip_sec_phase_2
from pfapi.api.mim import get_controlled_devices
from pfapi.api.interfaces import get_interfaces, get_interface_descriptors, add_interface
from pfapi.api.system import apply_dirty_config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def parse_args() -> argparse.Namespace:
    """
    Parses command line arguments.
    
    Returns:
        argparse.Namespace: Parsed command line arguments.
    """
    parser = argparse.ArgumentParser(
        description='Configure pfSense SD-WAN IPSec tunnels based on YAML configuration'
    )
    parser.add_argument(
        '--file', 
        type=str, 
        default='pfhq.yaml', 
        help='Path to the YAML configuration file'
    )
    parser.add_argument(
        '--state_file', 
        type=str, 
        default='pfhq.data', 
        help='Path to the state file'
    )
    parser.add_argument(
        '--dry_run', 
        action='store_true', 
        help='Perform a dry run without making API calls'
    )
    return parser.parse_args()


def load_config(yaml_file: str) -> Dict[str, Any]:
    """Loads the YAML configuration file and returns it as a Python dictionary.
    
    Args:
        yaml_file: The path to the YAML configuration file.
        
    Returns:
        The loaded configuration data as a Python dictionary.
        
    Raises:
        FileNotFoundError: If the YAML file doesn't exist.
        yaml.YAMLError: If the YAML file is malformed.
    """
    try:
        logging.info(f"Loading configuration from {yaml_file}")
        with open(yaml_file, 'r') as file:
            config = yaml.safe_load(file)
            validate_config(config)
            return config
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {yaml_file}")
        raise
    except yaml.YAMLError as e:
        logging.error(f"Error parsing YAML file: {e}")
        raise


def validate_config(config: Dict[str, Any]) -> None:
    """Validates the configuration structure.
    
    Args:
        config: The loaded configuration data.
        
    Raises:
        ValueError: If required fields are missing.
    """
    required_fields = ['api_server', 'firewalls', 'tunnels_network', 'hint_prefix', 'ipsec']
    missing_fields = [field for field in required_fields if field not in config]
    
    if missing_fields:
        raise ValueError(f"Missing required configuration fields: {', '.join(missing_fields)}")
    
    if not config['firewalls']:
        raise ValueError("At least one firewall must be defined")
    
    logging.info("Configuration validation passed")


def build_settings(data: Dict[str, Any]) -> Settings:
    """Builds the settings object for API interaction based on the loaded YAML data.
    
    Args:
        data: The loaded configuration data from the YAML file.
        
    Returns:
        A settings object configured for API interaction.
    """
    # If USER environment variable is not set, it defaults to admin.
    # CONTROLLER_URL cannot have a trailing slash, otherwise the API calls will fail.
    settings = get_settings()
    settings.CONTROLLER_URL = f"https://{data['api_server']}:8443"
    logging.info(f"Configured controller URL: {settings.CONTROLLER_URL}")
    return settings


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
    ipsectunnelsbyfirewall: Dict[str, List[Dict[str, str]]],
    ike_version: str,
    tunnel_index: Dict[str, Dict[str, Any]]
) -> Tuple[Dict[str, List[Phase1]], Dict[str, Dict[str, Any]]]:
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


def apply_tunnels_to_devices(
    device_children: Dict[str, Any],
    ipsectunnelcalls: Dict[str, List[Phase1]],
    tunnel_index: Dict[str, Dict[str, Any]],
    dry_run: bool = False
) -> None:
    """Applies Phase 1 and Phase 2 tunnel configurations to devices.
    
    Maps interface identities for each device, then pushes the Phase 1 and Phase 2
    configurations to the appropriate devices based on the firewall they belong to.
    After applying each Phase 1 configuration, it extracts the assigned IKE ID from
    the API response and updates the tunnel index for reference in Phase 2.
    
    Args:
        device_children: Mapping of device names to child API clients.
        ipsectunnelcalls: Mapping of firewall names to Phase 1 configurations.
        tunnel_index: Mapping of firewall names to tunnel details.
        dry_run: If True, skip actual API calls.
    """
    interfacestoidentity = {}

    for device_name, child in device_children.items():
        if device_name not in ipsectunnelcalls:
            logging.debug(f"No tunnels configured for device '{device_name}'")
            continue
        
        try:
            logging.info(f"Processing device: {device_name}")
            
            if dry_run:
                logging.info(f"[DRY RUN] Would fetch interfaces for {device_name}")
                logging.info(f"[DRY RUN] Would apply {len(ipsectunnelcalls[device_name])} tunnels to {device_name}")
                continue
            
            # Fetch interface mappings
            response = child.call(get_interfaces.sync).to_dict()
            interfacestoidentity[device_name] = {
                interface['assigned']: interface['identity']
                for interface in response['interfaces']
            }

            # Apply Phase 1 configurations
            for tunnel in ipsectunnelcalls[device_name]:
                tunnel.interface = interfacestoidentity[device_name][tunnel.interface]
                tunnel_name = str(tunnel.descr) if tunnel.descr else ""
                logging.info(f"Applying Phase 1 for tunnel: {tunnel_name}")
                
                response = child.call(set_ip_sec_phase_1.sync, body=tunnel).to_dict()
                
                # Extract IKE ID from response
                ike_id = response['msg'].split("Phase1 ", 1)[1].split(None, 1)[0]
                tunnel_index[device_name][tunnel_name]["phase2"].ikeid = ike_id
                logging.debug(f"Assigned IKE ID {ike_id} to tunnel {tunnel_name}")
            
            # Apply Phase 2 configurations
            for tunnel_name in tunnel_index[device_name]:
                logging.info(f"Applying Phase 2 for tunnel: {tunnel_name}")
                phase2 = tunnel_index[device_name][tunnel_name]["phase2"]
                child.call(set_ip_sec_phase_2.sync, body=phase2)
            
            logging.info(f"Successfully configured {len(ipsectunnelcalls[device_name])} tunnels on {device_name}")
            
        except Exception as e:
            logging.error(f"Error applying tunnels to device {device_name}: {e}")
            raise



def build_device_children(sessionClient: Any) -> Dict[str, Any]:
    """Builds a mapping of device names to child API clients for controlled devices.

    Args:
        sessionClient: An authenticated API client for the pfSense controller.
        
    Returns:
        A dictionary mapping device names to child API clients.
        
    Raises:
        Exception: If no online devices are found.
    """
    try:
        logging.info("Fetching controlled devices...")
        online_devices = sessionClient.call(get_controlled_devices.sync)
        
        device_children = {}
        for device in online_devices.devices:
            if device.device_id != "localhost":
                logging.info(f"Found device: {device.name} (ID: {device.device_id})")
                device_children[device.name] = sessionClient.createDeviceApiChild(
                    device_id=device.device_id
                )
        
        if not device_children:
            raise Exception("No online devices found (excluding localhost)")
        
        logging.info(f"Successfully connected to {len(device_children)} device(s)")
        return device_children
        
    except Exception as e:
        logging.error(f"Error building device children: {e}")
        raise
    

def turn_on_ipsec_tunnels(device_children: Dict[str, Any], dry_run: bool = False) -> None:
    """Turns on the IPSec tunnels on the devices by ensuring necessary interfaces are enabled.
    
    It retrieves the interface descriptors for each device, identifies the IPSec-related
    interfaces, and checks if they are already present in the device's interfaces. If any
    IPSec interfaces are missing, it creates and enables them using the API.
    
    Args:
        device_children: Mapping of device names to child API clients.
        dry_run: If True, skip actual API calls.
    """
    for device_name, child in device_children.items():
        try:
            logging.info(f"Enabling IPSec interfaces on device: {device_name}")
            
            if dry_run:
                logging.info(f"[DRY RUN] Would enable IPSec interfaces on {device_name}")
                continue
            
            # Get physical descriptors
            descriptors = child.call(get_interface_descriptors.sync).to_dict()["descriptors"]["physical"]
            ipsec_descriptors = {
                k: v for k, v in descriptors.items() if k.startswith("ipsec")
            }
            
            # Get current interfaces
            interfaces = child.call(get_interfaces.sync).to_dict()["interfaces"]
            existing_interface_names = [interface["if"] for interface in interfaces]
            
            # Determine which interfaces need to be created
            interfaces_to_be_made = [
                descriptor for descriptor in ipsec_descriptors.keys()
                if descriptor not in existing_interface_names
            ]
            
            if not interfaces_to_be_made:
                logging.info(f"All IPSec interfaces already enabled on {device_name}")
                continue
            
            # Create missing interfaces
            for interface in interfaces_to_be_made:
                logging.info(f"Creating interface: {interface}")
                new_interface = Interface()
                new_interface.if_ = interface
                new_interface.enable = True
                child.call(add_interface.sync, body=new_interface)
            
            logging.info(f"Created {len(interfaces_to_be_made)} IPSec interface(s) on {device_name}")
            
        except Exception as e:
            logging.error(f"Error enabling IPSec interfaces on {device_name}: {e}")
            raise
       
       
def apply_changes_to_all_devices(device_children: Dict[str, Any], dry_run: bool = False) -> None:
    """Applies pending changes to all devices to activate the new configurations.
    
    Args:
        device_children: Mapping of device names to child API clients.
        dry_run: If True, skip actual API calls.
    """
    body = ApplyDirtyConfigRequest()
    ApplyDirtyConfigRequest.apply = True
    for device_name, child in device_children.items():
        try:
            logging.info(f"Applying changes on device: {device_name}")
            
            if dry_run:
                logging.info(f"[DRY RUN] Would apply changes on {device_name}")
                continue
            
            child.call(apply_dirty_config.sync, body=body)
            logging.info(f"Changes applied successfully on {device_name}")
            
        except Exception as e:
            logging.error(f"Error applying changes on {device_name}: {e}")
            raise
        

def main() -> None:
    """Main function to orchestrate the workflow of loading configuration,
    building tunnels, and applying them to devices via the API.
    """
    try:
        args = parse_args()
        
        if args.dry_run:
            logging.info("=" * 60)
            logging.info("DRY RUN MODE - No changes will be made")
            logging.info("=" * 60)
        
        # Load and validate configuration
        data = load_config(args.file)
        settings = build_settings(data)

        # Build tunnel configurations
        tags = collect_tags(data)
        tagstointerfaces = build_tag_interface_map(data, tags)

        ipsectunnels = build_ipsec_tunnels(
            tagstointerfaces,
            data["tunnels_network"],
            data["hint_prefix"],
        )
        
        ipsectunnelsbyfirewall = build_tunnel_calls(ipsectunnels, data["firewalls"])
        tunnel_index = build_tunnel_index(ipsectunnelsbyfirewall)
        ipsectunnelcalls, tunnel_index = build_ipsec_calls(
            ipsectunnelsbyfirewall,
            data["ipsec"]["ike"],
            tunnel_index
        )

        if args.dry_run:
            logging.info("Configuration built successfully")
            logging.info(f"Total tunnels to be created: {len(ipsectunnels)}")
            for fw, tunnels in ipsectunnelsbyfirewall.items():
                logging.info(f"  {fw}: {len(tunnels)} tunnels")
            logging.info("Dry run complete - exiting without making API calls")
            return

        # Initialize API client and authenticate
        logging.info("Initializing API client...")
        sessionClient = RequestClient(controller_url=settings.CONTROLLER_URL)
        
        if not sessionClient.login(settings.USER, settings.PASSWORD):
            logging.error("Login failed")
            sys.exit(1)
        
        logging.info("Successfully authenticated")

        # Build device clients and apply configurations
        device_children = build_device_children(sessionClient)
        apply_tunnels_to_devices(device_children, ipsectunnelcalls, tunnel_index, args.dry_run)
        turn_on_ipsec_tunnels(device_children, args.dry_run)
        apply_changes_to_all_devices(device_children, args.dry_run)

        # Stop the refresh timer to exit cleanly
        sessionClient.stop()
        
        logging.info("=" * 60)
        logging.info("Configuration completed successfully")
        logging.info("=" * 60)
        
    except KeyboardInterrupt:
        logging.warning("\nOperation cancelled by user")
        sys.exit(130)
    except Exception as e:
        logging.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()