# Import libraries for configuration, API interaction, and network calculations
import yaml
import pprint
import argparse
import src.utils as utils
from src.helper_funcs import *
import ipcalc
import sys

# Import pfSense API models and methods for IPSec and device management
from pfapi.models import *
from pfapi.api.vpn import set_ip_sec_phase_1
from pfapi.api.mim import get_controlled_devices
from pfapi.api.interfaces import get_interfaces

# Parse command line arguments to get the configuration file path
parser = argparse.ArgumentParser()
parser.add_argument('--file', type=str, default='pfhq.yaml', help='Path to the YAML configuration file')
args = parser.parse_args()

# Load the YAML configuration file
yaml_file = args.file
with open(yaml_file, 'r') as file:
    data = yaml.safe_load(file)

# Configure API settings: URL to the pfSense controller
# If USER environment variable is not set, it defaults to admin
# CONTROLLER_URL cannot have a trailing slash, otherwise the API calls will fail
settings = get_settings()
settings.CONTROLLER_URL = "https://" + data["api_server"] + ":" + "8443"

# Extract all unique tags from all interfaces across all firewalls
tags = set()
for firewall in data["firewalls"]:
    for interface in firewall["interfaces"]:
        tags.update(interface["tags"])

# Create a mapping of each tag to all interfaces that have that tag
# This allows us to identify which interfaces should be tunneled together
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

# Create IPSec tunnels: for each tag, create tunnels between all pairs of interfaces on different firewalls
# Assign unique IP addresses from the configured tunnel network to each tunnel endpoint
ipsectunnels = []
ipcounter = 0
iptoiterate = data["tunnels_network"]
for tag, interfaces in tagstointerfaces.items():  # For each tag
    # Create tunnels for all unique pairs of interfaces
    for i in range(len(interfaces)):
        for j in range(i + 1, len(interfaces)):
            # Only create tunnels between interfaces on different firewalls
            if interfaces[i]["firewall"] != interfaces[j]["firewall"]:
                # Configure first endpoint of the tunnel
                interface1 = dict(interfaces[i])
                interface1["tunnel_name"] = f"{data['hint_prefix']}_{interfaces[i]['interface']}-{interfaces[j]['firewall']}-{interfaces[j]['interface']}"
                interface1["tunnel_ip"] = str(ipcalc.Network(iptoiterate) + ipcounter)
                
                # Configure second endpoint of the tunnel
                interface2 = dict(interfaces[j])
                interface2["tunnel_name"] = f"{interfaces[j]['interface']}-{interfaces[i]['firewall']}-{interfaces[i]['interface']}"
                interface2["tunnel_ip"] = str(ipcalc.Network(iptoiterate) + ipcounter + 1)  # type: ignore
                ipcounter += 2
                
                # Store tunnel configuration with pre-shared key
                ipsectunnels.append({
                    "tag": tag,
                    "interface1": interface1,
                    "interface2": interface2,
                    "secret": utils.generate_random_password(24),
                })


# Organize tunnels by firewall to simplify API calls
# Each firewall will have a list of tunnels it needs to establish
ipsectunnelsbyfirewall = {}
for firewall in data["firewalls"]:
    ipsectunnelsbyfirewall[firewall["name"]] = []

# Initialize dictionary to store Phase 1 configuration calls for each firewall
ipsectunnelcalls = {firewall["name"]: [] for firewall in data["firewalls"]}

# Build configuration dictionaries for each endpoint of each tunnel
for tunnel in ipsectunnels:
    firewall1 = tunnel["interface1"]["firewall"]
    firewall2 = tunnel["interface2"]["firewall"]
    
    # Configuration for first firewall's tunnel endpoint
    call1 = {
        "name": tunnel["interface1"]["tunnel_name"],
        "interface": tunnel["interface1"]["interface"],
        "remote_gateway": tunnel["interface2"]["ip"],
        "pre_shared_key": tunnel["secret"],
        "tunnel_ip": tunnel["interface1"]["tunnel_ip"]
    }
    
    # Configuration for second firewall's tunnel endpoint
    call2 = {
        "name": tunnel["interface2"]["tunnel_name"],
        "interface": tunnel["interface2"]["interface"],
        "remote_gateway": tunnel["interface1"]["ip"],
        "pre_shared_key": tunnel["secret"],
        "tunnel_ip": tunnel["interface2"]["tunnel_ip"]
    }
    
    # Assign each endpoint to its respective firewall
    ipsectunnelsbyfirewall[firewall1].append(call1)
    ipsectunnelsbyfirewall[firewall2].append(call2)

# Create Phase 1 (IKE) configurations for each IPSec tunnel
# Phase 1 handles the initial key exchange and tunnel negotiation
for firewall, tunnels in ipsectunnelsbyfirewall.items():
    for tunnel in tunnels:
        # Create a new Phase 1 object with the configured IKE version
        test1 = Phase1(iketype=data["ipsec"]["ike"])
        
        # Configure basic tunnel parameters
        test1.disabled = False
        test1.descr = tunnel["name"]
        test1.interface = tunnel["interface"]
        test1.remote_gateway = tunnel["remote_gateway"]
        test1.pre_shared_key = tunnel["pre_shared_key"]
        
        # Set authentication and protocol settings
        test1.authentication_method = "pre_shared_key"
        test1.protocol = "inet"
        test1.myid_type = "myaddress"
        test1.peerid_type = "peeraddress"
        
        # Configure timing and keepalive settings
        test1.lifetime = 28800  # 8 hours
        test1.nat_traversal = "on"
        test1.mobike = "off"
        test1.gw_duplicates = True
        test1.prfselect_enable = False
        
        # Configure dead peer detection for tunnel health
        test1.dpd_delay = 10
        test1.dpd_maxfail = 5
        
        # Set encryption algorithm (AES-128) and hashing (SHA256) with DH group 14
        encryption_dict = {'item': [{'dhgroup': '14',
                             'encryption_algorithm': {'keylen': '128',
                                                      'name': 'aes'},
                             'hash_algorithm': 'sha256'}]}
        test1.encryption = Phase1Encryption.from_dict(encryption_dict)
        
        # Add the configured Phase 1 to the API calls for this firewall
        ipsectunnelcalls[firewall].append(test1)

# Initialize API client and authenticate with the pfSense controller
sessionClient = RequestClient(controller_url=settings.CONTROLLER_URL)

# Attempt to login; exit if authentication fails
if not sessionClient.login(settings.USER, settings.PASSWORD):
    print("Login failed... quitting")
    sys.exit(1)

# Retrieve list of all online managed devices from the controller
online_devices = sessionClient.call(get_controlled_devices.sync)

# Create an index for quick lookup of tunnels by firewall name and tunnel description
tunnel_index = {
    fw: {t["name"]: t for t in tunnels}
    for fw, tunnels in ipsectunnelsbyfirewall.items()
}

# Map interface names (like "ge-0/0/0") to their internal identity numbers required by the API
interfacestoidentity = {}

# Process each online device that has configured tunnels
for device in online_devices.devices:
    # Skip localhost and devices not in our tunnel configuration
    if device.device_id != "localhost" and device.name in ipsectunnelcalls:
        # Create a device-specific API client
        child = sessionClient.createDeviceApiChild(device_id=device.device_id)
        
        # Retrieve interface information from the device
        response = child.call(get_interfaces.sync).to_dict()
        testresponse = child.call(get_status.sync).to_dict()
        pprint.pprint(testresponse)
        
        # Build mapping of interface names to their identity numbers
        interfacestoidentity[device.name] = {}
        for interface in response['interfaces']:
            interfacestoidentity[device.name][interface['assigned']] = interface['identity']
        
        # Configure each tunnel for this device
        for tunnel in ipsectunnelcalls[device.name]:
            # Convert interface name to identity number for API call
            tunnel.interface = interfacestoidentity[device.name][tunnel.interface]
            print(device.name)
            
            # Send Phase 1 configuration to the device via API
            response = child.call(set_ip_sec_phase_1.sync, body=tunnel).to_dict()
            
            # Extract and store the IKE ID returned by the device for this tunnel
            tunnel_index[device.name][tunnel.descr]["ike_id"] = int(response['msg'].split("Phase1 ", 1)[1].split(None, 1)[0])

# Stop the refresh timer to exit; otherwise it will wait until the timer event happens
sessionClient.stop()