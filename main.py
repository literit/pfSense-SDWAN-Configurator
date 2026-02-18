# Import libraries for configuration, API interaction, and network calculations
import yaml
import argparse
import src.utils as utils
from src.helper_funcs import *
import ipcalc
import sys
from pprint import pprint

# Import pfSense API models and methods for IPSec and device management
from pfapi.models import *
from pfapi.api.vpn import set_ip_sec_phase_1, set_ip_sec_phase_2
from pfapi.api.mim import get_controlled_devices
from pfapi.api.interfaces import get_interfaces, get_interface_descriptors, add_interface

def parse_args():
    """
    Parses command line arguments.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', type=str, default='pfhq.yaml', help='Path to the YAML configuration file')
    parser.add_argument('--state_file', type=str, default='pfhq.data', help='Path to the state file')
    parser.add_argument('--dry_run', action='store_true', help='Perform a dry run without making API calls')
    return parser.parse_args()


def load_config(yaml_file):
    """ Loads the YAML configuration file and returns it as a Python dictionary.
    
    Args:
        yaml_file (str): The path to the YAML configuration file.
    Returns:
        dict: The loaded configuration data as a Python dictionary.
    """
    with open(yaml_file, 'r') as file:
        return yaml.safe_load(file)


def build_settings(data):
    """ Builds the settings object for API interaction based on the loaded YAML data.
    
    Args:
        data (dict): The loaded configuration data from the YAML file.
    Returns:
        Settings: A settings object configured for API interaction.
    """
    # If USER environment variable is not set, it defaults to admin.
    # CONTROLLER_URL cannot have a trailing slash, otherwise the API calls will fail.
    settings = get_settings()
    settings.CONTROLLER_URL = "https://" + data["api_server"] + ":" + "8443"
    return settings


def collect_tags(data):
    """Collects all unique tags from the interfaces defined in the configuration data.
    
    Args:
        data (dict): The loaded configuration data from the YAML file.
    Returns:
        set: A set of unique tags found across all interfaces in the configuration.
    """
    tags = set()
    for firewall in data["firewalls"]:
        for interface in firewall["interfaces"]:
            tags.update(interface["tags"])
    return tags


def build_tag_interface_map(data, tags):
    """Builds a mapping of tags to the interfaces that use them.
    
    Args:
        data (dict): The loaded configuration data from the YAML file.
        tags (set): A set of unique tags found across all interfaces in the configuration.
    Returns:
        dict: A dictionary mapping each tag to a list of interfaces that use it.
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
    return tagstointerfaces


def build_ipsec_tunnels(tagstointerfaces, tunnels_network, hint_prefix):
    """Builds a list of IPSec tunnels based on the mapping of tags to interfaces. For each tag, it creates tunnels between all pairs of interfaces that share that tag, ensuring that tunnels are only created between interfaces on different firewalls. Each tunnel is assigned a unique name and IP address from the specified tunnel network.
    
    Args:
        tagstointerfaces (dict): A dictionary mapping each tag to a list of interfaces that use it.
        tunnels_network (str): The network range to use for assigning tunnel IP addresses.
        hint_prefix (str): A prefix to use in the tunnel names for identification.
    Returns:
        list: A list of dictionaries, each representing an IPSec tunnel with its associated interfaces and configuration details.
    """
    ipsectunnels = []
    ipcounter = 0
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
    return ipsectunnels


def build_tunnel_calls(ipsectunnels, firewalls):
    """Organizes the IPSec tunnels by firewall to simplify API calls. For each tunnel, it creates two call objects (one for each firewall) with the necessary details for configuring the tunnel on that firewall. The resulting structure is a dictionary mapping each firewall name to a list of tunnel call objects that need to be applied to that firewall.
    
    Args:
        ipsectunnels (list): A list of dictionaries, each representing an IPSec tunnel with its associated interfaces and configuration details.
        firewalls (list): A list of firewall configurations from the loaded YAML data, each containing the firewall name and its interfaces.
    Returns:
        dict: A dictionary mapping each firewall name to a list of tunnel call objects that need to be applied to that firewall for configuring the IPSec tunnels.
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
    return ipsectunnelsbyfirewall


def make_ipsec_phases(tunnel, ike_version):
    """Creates a Phase 1 configuration object for a given tunnel and IKE version. The configuration is based on consistent defaults for all tunnels, with specific details filled in from the tunnel information. This includes settings for authentication, encryption, lifetime, and other parameters necessary for establishing the IPSec tunnel.
    
    Args:
        tunnel (dict): A dictionary containing the details of the tunnel, including its name, interface, remote gateway, and pre-shared key.
        ike_version (str): The IKE version to use for the Phase 1 configuration (e.g., "ikev2").
    Returns:
        Phase1: A Phase1 object configured with the appropriate settings for the given tunnel and IKE version, ready to be applied to the firewall via the API.
        Phase2: A Phase2 object configured with the appropriate settings for the given tunnel, ready to be applied to the firewall via the API.
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

    encryption_dict = {'item': [{'dhgroup': '14',
                         'encryption_algorithm': {'keylen': '128',
                                                  'name': 'aes'},
                         'hash_algorithm': 'sha256'}]}
    phase1.encryption = Phase1Encryption.from_dict(encryption_dict)
    
    phase2 = Phase2()
    # ikeid is the one that is needed to link phase 2 to phase 1, but it is not known until phase 1 is applied and the API response is received with the assigned ike_id. This will be updated in the tunnel index after applying phase 1.
    phase2.mode = "vti"
    localid_dict = {'type': 'network', 'address': ipcalc.IP(tunnel["tunnel_ip"]).dq, 'netbits': "31"}
    phase2.localid = Phase2LocalId.from_dict(localid_dict)
    remoteid_dict = {'type': 'network', 'address': ipcalc.IP(tunnel["remote_tunnel_ip"]).dq, 'netbits': "31"}
    phase2.remoteid = Phase2RemoteId.from_dict(remoteid_dict)
    phase2.protocol = "esp"
    phase2.encryption_algorithm_option = [EncryptionAlgorithm.from_dict({"name": "aes", "keylen": "128"}), EncryptionAlgorithm.from_dict({"name": "aes128gcm", "keylen": "128"})]
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


def build_ipsec_calls(ipsectunnelsbyfirewall, ike_version, tunnel_index):
    """Builds Phase 1 and Phase 2 configuration objects for all tunnels, organized by firewall.
    
    Args:
        ipsectunnelsbyfirewall (dict): A dictionary mapping each firewall name to a list of tunnel call details that need to be applied to that firewall.
        ike_version (str): The IKE version to use for all Phase 1 configurations (e.g., "ikev2").
        tunnel_index (dict): A dictionary mapping each firewall name to a dictionary of tunnel names to tunnel details, allowing for quick lookup of tunnels by firewall and name. This will be updated with the assigned IKE IDs after applying Phase 1 configurations.
    Returns:
        ipsectunnelcalls (dict): A dictionary mapping each firewall name to a list of Phase 1 configuration objects that need to be applied to that firewall for configuring the IPSec tunnels. Each Phase 1 object is created based on the corresponding tunnel details and the specified IKE version, ready to be applied to the firewall via the API.
        tunnel_index (dict): A dictionary mapping each firewall name to a dictionary of tunnel names to tunnel details, including the Phase 2 configuration objects, allowing for quick lookup of tunnels by firewall and name.
    """
    # Prepare Phase 1 objects per firewall.
    ipsectunnelcalls = {firewall: [] for firewall in ipsectunnelsbyfirewall}
    for firewall, tunnels in ipsectunnelsbyfirewall.items():
        for tunnel in tunnels:
            phase1, phase2 = make_ipsec_phases(tunnel, ike_version)
            ipsectunnelcalls[firewall].append(phase1)
            tunnel_index[firewall][tunnel["name"]]["phase2"] = phase2
    return ipsectunnelcalls, tunnel_index


def build_tunnel_index(ipsectunnelsbyfirewall):
    """Builds an index for quick lookup of tunnels by firewall name and description.

    Args:
        ipsectunnelsbyfirewall (dict): A dictionary mapping each firewall name to a list of tunnel call details that need to be applied to that firewall.

    Returns:
        dict: A dictionary mapping each firewall name to a dictionary of tunnel names to tunnel details, allowing for quick lookup of tunnels by firewall and name.
    """
    return {
        fw: {t["name"]: t for t in tunnels}
        for fw, tunnels in ipsectunnelsbyfirewall.items()
    }


def apply_tunnels_to_devices(device_children, ipsectunnelcalls, tunnel_index):
    """Applies Phase 1 tunnel configurations to devices. Maps interface identities for each device, and then pushes the Phase 1 configurations to the appropriate devices based on the firewall they belong to. After applying each Phase 1 configuration, it extracts the assigned IKE ID from the API response and updates the tunnel index for reference in later steps (such as configuring Phase 2).
    
    Args:
        device_children (dict): A dictionary mapping device names to child API clients.
        ipsectunnelcalls (dict): A dictionary mapping each firewall name to a list of Phase 1 configuration objects that need to be applied to that firewall for configuring the IPSec tunnels.
        tunnel_index (dict): A dictionary mapping each firewall name to a dictionary of tunnel names to tunnel details, allowing for quick lookup of tunnels by firewall and name.
    """
    interfacestoidentity = {}

    for device_name, child in device_children.items():
        if device_name in ipsectunnelcalls:
            response = child.call(get_interfaces.sync).to_dict()

            interfacestoidentity[device_name] = {}
            for interface in response['interfaces']:
                interfacestoidentity[device_name][interface['assigned']] = interface['identity']

            for tunnel in ipsectunnelcalls[device_name]:
                tunnel.interface = interfacestoidentity[device_name][tunnel.interface]
                response = child.call(set_ip_sec_phase_1.sync, body=tunnel).to_dict()
                tunnel_index[device_name][tunnel.descr]["phase2"].ikeid = response['msg'].split("Phase1 ", 1)[1].split(None, 1)[0]
            for tunnel in tunnel_index[device_name]:
                response = child.call(set_ip_sec_phase_2.sync, body=tunnel_index[device_name][tunnel]["phase2"])



def build_device_children(sessionClient):
    """Builds a mapping of device names to child API clients for controlled devices.

    Args:
        sessionClient (RequestClient): An authenticated API client for interacting with the pfSense controller.
    Returns:
        dict: A dictionary mapping device names to child API clients.
    """
    online_devices = sessionClient.call(get_controlled_devices.sync)
    device_children = {}
    for device in online_devices.devices:
        if device.device_id != "localhost":
            device_children[device.name] = sessionClient.createDeviceApiChild(device_id=device.device_id)
    return device_children
    

def turn_on_ipsec_tunnels(device_children):
    for child in device_children.items():
        descriptors = child.call(get_interface_descriptors.sync).to_dict()["descriptors"]["physical"]
        ipsec_descriptors = {k: v for k, v in descriptors.items() if k.startswith("ipsec")}
        interfaces = child.call(get_interfaces.sync).to_dict()["interfaces"]
        interfaces_to_be_made = [descriptor for descriptor in ipsec_descriptors.keys() if descriptor not in [interface["if"] for interface in interfaces]]
        for interface in interfaces_to_be_made:
            new_interface = Interface()
            new_interface.if_ = interface
            new_interface.enable = True
            child.call(add_interface.sync, body=new_interface)
        

def main():
    """Main function to orchestrate the workflow of loading configuration, building tunnels, and applying them to devices via the API."""
    args = parse_args()
    data = load_config(args.file)
    settings = build_settings(data)

    tags = collect_tags(data)
    tagstointerfaces = build_tag_interface_map(data, tags)

    ipsectunnels = build_ipsec_tunnels(
        tagstointerfaces,
        data["tunnels_network"],
        data["hint_prefix"],
    )
    ipsectunnelsbyfirewall = build_tunnel_calls(ipsectunnels, data["firewalls"])
    tunnel_index = build_tunnel_index(ipsectunnelsbyfirewall)
    ipsectunnelcalls, tunnel_index = build_ipsec_calls(ipsectunnelsbyfirewall, data["ipsec"]["ike"], tunnel_index)

    # Initialize API client and authenticate with the pfSense controller.
    sessionClient = RequestClient(controller_url=settings.CONTROLLER_URL)
    if not sessionClient.login(settings.USER, settings.PASSWORD):
        print("Login failed... quitting")
        sys.exit(1)

    device_children = build_device_children(sessionClient)
    
    apply_tunnels_to_devices(device_children, ipsectunnelcalls, tunnel_index)
    
    turn_on_ipsec_tunnels(device_children)

    # Stop the refresh timer to exit; otherwise it will wait until the timer event happens.
    sessionClient.stop()


if __name__ == "__main__":
    main()