import yaml
import pprint
import argparse
import src.utils as utils
import ipcalc
import json

parser = argparse.ArgumentParser()
parser.add_argument('--file', type=str, default='pfhq.yaml', help='Path to the YAML configuration file')
args = parser.parse_args()

yaml_file = args.file

with open(yaml_file, 'r') as file:
    data = yaml.safe_load(file)

tags = set()
for firewall in data["firewalls"]:
    for interface in firewall["interfaces"]:
        tags.update(interface["tags"])

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

# Create ips for each tunnel and change the tunnel_name so that it covers both ends 
ipsectunnels = []
ipcounter = 0
# the ip for each tunnel starts at the base address of the 
iptoiterate = data["tunnels_network"]
for tag, interfaces in tagstointerfaces.items(): # for each tag
    for i in range(len(interfaces)):
        for j in range(i + 1, len(interfaces)):
            if interfaces[i]["firewall"] != interfaces[j]["firewall"]:
                interface1 = dict(interfaces[i])
                interface1["tunnel_name"] = f"{interfaces[i]['interface']}-{interfaces[j]['firewall']}-{interfaces[j]['interface']}"
                interface1["tunnel_ip"] = str(ipcalc.Network(iptoiterate) + ipcounter)
                interface2 = dict(interfaces[j])
                interface2["tunnel_name"] = f"{interfaces[j]['interface']}-{interfaces[i]['firewall']}-{interfaces[i]['interface']}"
                interface2["tunnel_ip"] = str(ipcalc.Network(iptoiterate) + ipcounter + 1)
                ipcounter += 2
                ipsectunnels.append({
                    "tag": tag,
                    "interface1": interface1,
                    "interface2": interface2,
                    "secret": utils.generate_random_password(24),
                })


# create list of tunnels to make the p1 and p2 entries for each tunnel
# I need to first go through and seperate the tunnels by firewall
ipsectunnelsbyfirewall = {}
for firewall in data["firewalls"]:
    ipsectunnelsbyfirewall[firewall["name"]] = []
pprint.pp(ipsectunnelsbyfirewall)
ipsectunnelsjsoncalls = {firewall["name"]: [] for firewall in data["firewalls"]}

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

# Theoretical json call for creating a p1 entry for a tunnel
# {"disabled":false,"descr":"' + name + '","iketype":"ikev2","protocol":"inet","interface":"' + interface + '","remote_gateway":"' + remote_Gateway + '","authentication_method":"pre_shared_key","myid_type":"myaddress","peerid_type":"peeraddress","pre_shared_key":"' + pre_shared_key + '","encryption":{"item":[{"encryption_algorithm":{"name":"aes","keylen":"128"},"hash_algorithm":"sha256","dhgroup":"14"}]},"lifetime":28800,"nat_traversal":"on","mobike":"off","gw_duplicates":true,"prfselect_enable":false}
# Needed variables are name, interface, remote_Gateway, pre_shared_key

# turn the tunnels into json calls for creating p1 entries

for firewall, tunnels in ipsectunnelsbyfirewall.items():
    for tunnel in tunnels:
        name = tunnel["name"]
        interface = tunnel["interface"]
        remote_Gateway = tunnel["remote_gateway"]
        pre_shared_key = tunnel["pre_shared_key"]
        json_call = {
            "disabled": False,
            "descr": name,
            "iketype": data["ipsec"]["ike"],
            "protocol": "inet",
            "interface": interface,
            "remote_gateway": remote_Gateway,
            "authentication_method": "pre_shared_key",
            "myid_type": "myaddress",
            "peerid_type": "peeraddress",
            "pre_shared_key": pre_shared_key,
            "encryption": {
                "item": [
                    {
                        "encryption_algorithm": {
                            "name": "aes",
                            "keylen": 128
                        },
                        "hash_algorithm": "sha256",
                        "dhgroup": 14
                    }
                ]
            },
            "lifetime": 28800,
            "nat_traversal": "on",
            "mobike": "off",
            "gw_duplicates": True,
            "prfselect_enable": False
        }
        # print(json.dumps(json_call, indent=4))
        pprint.pp(ipsectunnelsjsoncalls)
        ipsectunnelsjsoncalls[firewall].append(json_call)
        

pprint.pprint(ipsectunnelsjsoncalls)

