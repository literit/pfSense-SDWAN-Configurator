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
- `ipsec.p1_encryption`: Phase 1 encryption algorithm name (default: `aes`)
- `ipsec.p1_encryption_bits`: Phase 1 key length (default: `128`)
- `ipsec.p1_hash`: Phase 1 hash algorithm (default: `sha256`)
- `ipsec.p1_group`: Phase 1 DH group (default: `14`)
- `ipsec.p2_encryption`: Phase 2 encryption algorithm name (default: `aes`)
- `ipsec.p2_encryption_bits`: Phase 2 key length (default: `128`)
- `ipsec.p2_hash`: Phase 2 hash algorithm (default: `sha256`)
- `ipsec.p2_group`: Phase 2 PFS group (default: `14`)
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
  p1_encryption: "aes256gcm"
  p1_encryption_bits: 256
  p1_hash: "sha256"
  p1_group: 14
  p2_encryption: "aes256gcm"
  p2_encryption_bits: 256
  p2_hash: "hmac_sha256"
  p2_group: 14
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

Persist and reuse tunnel IP allocations (default state file: `pfhq.data`):
```bash
python main.py --file pfhq.yaml --state_file pfhq.data
```

## How it works
For every tag, the tool pairs interfaces on different firewalls, generates a unique
pre-shared key, assigns /31 tunnel IPs from `tunnels_network`, and applies IPSec
Phase 1/Phase 2 settings via the pfSense controller API.
