"""Gateway configuration and API calls module."""

import logging
from typing import Any, Dict

from pfapi.api.interfaces import get_interfaces
from pfapi.api.system import add_gateway
from pfapi.models import Gateway


def _get_phase2_gateway_ip(phase2: Any, tunnel_data: Dict[str, Any]) -> str:
	"""Returns the gateway IP for a tunnel based on its Phase 2 configuration."""
	remoteid = getattr(phase2, "remoteid", None)
	remote_address = getattr(remoteid, "address", None)
	if remote_address:
		return str(remote_address)

	if "remote_tunnel_ip" in tunnel_data and tunnel_data["remote_tunnel_ip"]:
		return str(tunnel_data["remote_tunnel_ip"])

	raise ValueError("Unable to determine gateway IP from IPSec Phase 2 data")


def apply_gateways_to_devices(
	device_children: Dict[str, Any],
	tunnel_index: Dict[str, Dict[str, Any]],
	dry_run: bool = False,
) -> None:
	"""Creates one gateway per tunnel on each device.

	The gateway IP is sourced from the IPSec Phase 2 remote network address, and
	the gateway is attached to the matching IPSec interface derived from the
	assigned IKE ID.

	Args:
		device_children: Mapping of device names to child API clients.
		tunnel_index: Mapping of firewall names to tunnel details.
		dry_run: If True, skip actual API calls.
	"""
	for device_name, child in device_children.items():
		tunnels_for_device = tunnel_index.get(device_name, {})
		if not tunnels_for_device:
			logging.debug(f"No tunnel index entries for device '{device_name}'")
			continue

		try:
			logging.info(f"Creating gateways on device: {device_name}")

			if dry_run:
				logging.info(
					"[DRY RUN] Would create %d gateways on %s",
					len(tunnels_for_device),
					device_name,
				)
				continue

			interfaces_response = child.call(get_interfaces.sync).to_dict()
			interfaces = interfaces_response.get("interfaces", [])
			interfaces_by_device = {
				interface.get("if"): interface
				for interface in interfaces
				if interface.get("if")
			}

			for tunnel_name, tunnel_data in tunnels_for_device.items():
				phase2 = tunnel_data.get("phase2")
				if phase2 is None:
					logging.warning(
						"Skipping gateway for tunnel '%s' on '%s': missing phase2",
						tunnel_name,
						device_name,
					)
					continue

				ikeid = str(getattr(phase2, "ikeid", "")).strip()
				if not ikeid:
					logging.warning(
						"Skipping gateway for tunnel '%s' on '%s': missing ikeid",
						tunnel_name,
						device_name,
					)
					continue

				interface_device = f"ipsec{ikeid}"
				interface_info = interfaces_by_device.get(interface_device, {})
				interface_assigned = interface_info.get("assigned", f"OPT{ikeid}")
				interface_identity = interface_info.get("identity", f"opt{ikeid}")

				gateway_ip = _get_phase2_gateway_ip(phase2, tunnel_data)

				gateway = Gateway(gateway=gateway_ip)
				gateway.disabled = False
				gateway.interface_identity = interface_identity
				gateway.interface_assigned = interface_assigned
				gateway.interface_device = interface_device
				gateway.ipprotocol = "inet"
				gateway.name = tunnel_name
				gateway.monitor_disable = False
				gateway.action_disable = False
				gateway.nonlocalgateway = False
				gateway["dpinger_dont_add_static_route"] = False
				gateway["force_down"] = False
				gateway["_show_advanced"] = True

				child.call(add_gateway.sync, body=gateway)
				logging.info(
					"Created gateway '%s' (%s) on '%s' via %s",
					tunnel_name,
					gateway_ip,
					device_name,
					interface_device,
				)

		except Exception as e:
			logging.error(f"Error creating gateways on device {device_name}: {e}")
			raise
