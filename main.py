import yaml
import pprint
import argparse
import src.utils as utils
import ipcalc

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


# create list of calls to make the p1 and p2 entries for each tunnel
# I need to first go through and seperate the calls by firewall
ipsectunnelcalls = {}
for firewall in data["firewalls"]:
    ipsectunnelcalls[firewall["name"]] = []
for tunnel in ipsectunnels:
    

pprint.pprint(ipsectunnels)