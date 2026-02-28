# pfSense-SDWAN-Configurator

Automates pfSense SD-WAN IPSec VTI tunnel creation across multiple firewalls using the pfSense controller API.

## Features
- Builds tunnels between interfaces that share tags across different firewalls.
- Generates /31 tunnel IPs from a configurable network pool.
- Pushes Phase 1/Phase 2 IPSec configuration and enables IPSec interfaces.
- Supports dry runs without making API changes.

## Requirements
- Python 3.9+
- Access to a pfSense controller with API enabled

## Installation
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration
The tool reads a YAML file (default: `pfhq.yaml`) and expects these keys:
- `api_server`: Controller hostname or IP (used as `https://<api_server>:8443`)
- `tunnels_network`: CIDR for tunnel IP allocation (e.g., `10.200.0.0/24`)
- `hint_prefix`: Prefix for tunnel names
- `ipsec.ike`: IKE version (e.g., `ikev2`)
- `firewalls[]`: Firewall definitions
  - `name`: Firewall name (must match controller device name)
  - `interfaces[]`:
    - `name`: Interface name on the firewall
    - `ip`: Interface IP address
    - `tags`: List of tags used to form tunnels

Example:
```yaml
api_server: "10.100.0.38"
tunnels_network: "10.200.0.0/24"
hint_prefix: "sdwan"
ipsec:
  ike: "ikev2"
firewalls:
  - name: "fw-a"
    interfaces:
      - name: "wan1"
        ip: "203.0.113.10"
        tags: ["mpls", "internet"]
  - name: "fw-b"
    interfaces:
      - name: "wan1"
        ip: "198.51.100.10"
        tags: ["mpls"]
```

### Credentials
Set the controller password in the environment. The user defaults to `admin`.
```bash
export PASSWORD="your-controller-password"
```

## Usage
```bash
python main.py --file pfhq.yaml
```

Dry run (builds config without API calls):
```bash
python main.py --file pfhq.yaml --dry_run
```

> Note: `--state_file` is reserved for future use and is not currently applied.

## How it works
For every tag, the tool pairs interfaces on different firewalls, generates a unique
pre-shared key, assigns /31 tunnel IPs from `tunnels_network`, and applies IPSec
Phase 1/Phase 2 settings via the pfSense controller API.
