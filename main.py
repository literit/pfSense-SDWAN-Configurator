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
from pfapi.api.vpn import set_ip_sec_phase_1
from pfapi.api.mim import get_controlled_devices
from pfapi.api.interfaces import get_interfaces

def parse_args():
    # Parse command line arguments.
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', type=str, default='pfhq.yaml', help='Path to the YAML configuration file')
    parser.add_argument('--state_file', type=str, default='pfhq.data', help='Path to the state file')
    parser.add_argument('--dry_run', action='store_true', help='Perform a dry run without making API calls')
    return parser.parse_args()


def load_config(yaml_file):
    # Load the YAML configuration file.
    with open(yaml_file, 'r') as file:
        return yaml.safe_load(file)


def build_settings(data):
    # Configure API settings based on the loaded YAML data.
    # If USER environment variable is not set, it defaults to admin.
    # CONTROLLER_URL cannot have a trailing slash, otherwise the API calls will fail.
    settings = get_settings()
    settings.CONTROLLER_URL = "https://" + data["api_server"] + ":" + "8443"
    return settings


def collect_tags(data):
    # Extract all unique tags from all interfaces across all firewalls.
    tags = set()
    for firewall in data["firewalls"]:
        for interface in firewall["interfaces"]:
            tags.update(interface["tags"])
    return tags


def build_tag_interface_map(data, tags):
    # Map each tag to the interfaces that use it.
    # This allows us to easily find which interfaces should be connected by tunnels based on shared tags.
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
    # Create IPSec tunnels: for each tag, create tunnels between all pairs of interfaces.
    # Assign unique IP addresses from the configured tunnel network to each tunnel endpoint.
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
                        f"{interfaces[j]['interface']}"
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
    # Organize tunnels by firewall to simplify API calls.
    ipsectunnelsbyfirewall = {firewall["name"]: [] for firewall in firewalls}
    for tunnel in ipsectunnels:
        firewall1 = tunnel["interface1"]["firewall"]
        firewall2 = tunnel["interface2"]["firewall"]

        call1 = {
            "name": tunnel["interface1"]["tunnel_name"],
            "interface": tunnel["interface1"]["interface"],
            "remote_gateway": tunnel["interface2"]["ip"],
            "pre_shared_key": tunnel["secret"],
            "tunnel_ip": tunnel["interface1"]["tunnel_ip"]
        }
        call2 = {
            "name": tunnel["interface2"]["tunnel_name"],
            "interface": tunnel["interface2"]["interface"],
            "remote_gateway": tunnel["interface1"]["ip"],
            "pre_shared_key": tunnel["secret"],
            "tunnel_ip": tunnel["interface2"]["tunnel_ip"]
        }

        ipsectunnelsbyfirewall[firewall1].append(call1)
        ipsectunnelsbyfirewall[firewall2].append(call2)
    return ipsectunnelsbyfirewall


def make_phase1(tunnel, ike_version):
    # Create a Phase 1 object with consistent defaults.
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
    return phase1


def build_phase1_calls(ipsectunnelsbyfirewall, ike_version):
    # Prepare Phase 1 objects per firewall.
    ipsectunnelcalls = {firewall: [] for firewall in ipsectunnelsbyfirewall}
    for firewall, tunnels in ipsectunnelsbyfirewall.items():
        for tunnel in tunnels:
            ipsectunnelcalls[firewall].append(make_phase1(tunnel, ike_version))
    return ipsectunnelcalls


def build_tunnel_index(ipsectunnelsbyfirewall):
    # Create an index for quick lookup of tunnels by firewall name and description.
    return {
        fw: {t["name"]: t for t in tunnels}
        for fw, tunnels in ipsectunnelsbyfirewall.items()
    }


def apply_tunnels_to_devices(sessionClient, ipsectunnelcalls, tunnel_index):
    # Retrieve devices, map interface identities, then push Phase 1 configs.
    online_devices = sessionClient.call(get_controlled_devices.sync)
    interfacestoidentity = {}

    for device in online_devices.devices:
        if device.device_id != "localhost" and device.name in ipsectunnelcalls:
            child = sessionClient.createDeviceApiChild(device_id=device.device_id)
            response = child.call(get_interfaces.sync).to_dict()

            interfacestoidentity[device.name] = {}
            for interface in response['interfaces']:
                interfacestoidentity[device.name][interface['assigned']] = interface['identity']

            for tunnel in ipsectunnelcalls[device.name]:
                tunnel.interface = interfacestoidentity[device.name][tunnel.interface]
                print(device.name)

                response = child.call(set_ip_sec_phase_1.sync, body=tunnel).to_dict()
                tunnel_index[device.name][tunnel.descr]["ike_id"] = int(
                    response['msg'].split("Phase1 ", 1)[1].split(None, 1)[0]
                )


def main():
    # High-level workflow: load config, build tunnels, then apply to devices.
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
    ipsectunnelcalls = build_phase1_calls(ipsectunnelsbyfirewall, data["ipsec"]["ike"])

    # Initialize API client and authenticate with the pfSense controller.
    sessionClient = RequestClient(controller_url=settings.CONTROLLER_URL)
    if not sessionClient.login(settings.USER, settings.PASSWORD):
        print("Login failed... quitting")
        sys.exit(1)

    tunnel_index = build_tunnel_index(ipsectunnelsbyfirewall)
    apply_tunnels_to_devices(sessionClient, ipsectunnelcalls, tunnel_index)

    # Stop the refresh timer to exit; otherwise it will wait until the timer event happens.
    sessionClient.stop()


if __name__ == "__main__":
    main()