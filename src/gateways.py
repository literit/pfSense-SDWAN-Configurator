"""Gateway configuration and API calls module."""

import logging
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional

from pfapi.api.interfaces import get_interfaces
from pfapi.api.system import add_gateway, add_gateway_group
from pfapi.models import Gateway, GatewayGroup, GatewayGroupPriority


def _sanitize_gateway_name(name: str) -> str:
	"""Removes special characters from a gateway name."""
	cleaned = re.sub(r"[^\w]", "", str(name))
	return cleaned


def _is_bad_gateway_result(result: Any) -> bool:
	"""Returns True when an API result indicates gateway creation failure."""
	if result is None:
		return False

	if isinstance(result, dict):
		status = result.get("status") or result.get("status_code") or result.get("code")
		if isinstance(status, int) and status >= 400:
			return True
		if result.get("error") or result.get("errors"):
			return True
		msg = result.get("msg") or result.get("message")
		if isinstance(msg, str) and "bad request" in msg.lower():
			return True
		return False

	for attr in ("status", "status_code", "code"):
		value = getattr(result, attr, None)
		if isinstance(value, int) and value >= 400:
			return True

	msg = getattr(result, "msg", None) or getattr(result, "message", None)
	if isinstance(msg, str) and "bad request" in msg.lower():
		return True

	if result.__class__.__name__.lower() == "error":
		return True

	return False


def _get_phase2_gateway_ip(phase2: Any, tunnel_data: Dict[str, Any]) -> str:
	"""Returns the gateway IP for a tunnel based on its Phase 2 configuration."""
	remoteid = getattr(phase2, "remoteid", None)
	remote_address = getattr(remoteid, "address", None)
	if remote_address:
		return str(remote_address)

	if "remote_tunnel_ip" in tunnel_data and tunnel_data["remote_tunnel_ip"]:
		return str(tunnel_data["remote_tunnel_ip"])

	raise ValueError("Unable to determine gateway IP from IPSec Phase 2 data")


def _get_remote_firewall_name(tunnel_name: str, tunnel_data: Dict[str, Any]) -> Optional[str]:
	"""Returns destination firewall name for a tunnel when available."""
	remote_firewall = tunnel_data.get("remote_firewall")
	if remote_firewall:
		return str(remote_firewall)

	parts = str(tunnel_name).split("_")
	if len(parts) >= 4:
		return str(parts[-2])

	return None


def _make_gateway_group_name(remote_firewall_name: str) -> str:
	"""Builds a valid gateway-group name from a remote firewall name."""
	sanitized_remote_name = _sanitize_gateway_name(remote_firewall_name)
	if not sanitized_remote_name:
		sanitized_remote_name = "remote"
	return f"To_{sanitized_remote_name}"


def apply_gateways_to_devices(
	device_children: Dict[str, Any],
	tunnel_index: Dict[str, Dict[str, Any]],
	dry_run: bool = False,
) -> None:
	"""Creates one gateway per tunnel on each device.

	The gateway IP is sourced from the IPSec Phase 2 remote network address, and
	the gateway is attached to the matching IPSec interface. Interface metadata
	is read from tunnel_index when available and falls back to live interface
	lookup derived from IKE ID.

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
			groups_to_gateways: Dict[str, List[str]] = defaultdict(list)

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

				interface_device = str(tunnel_data.get("interface_device") or f"ipsec{ikeid}")
				interface_info = interfaces_by_device.get(interface_device, {})
				interface_assigned = str(
					tunnel_data.get("interface_assigned")
					or interface_info.get("assigned", f"OPT{ikeid}")
				)
				interface_identity = str(
					tunnel_data.get("interface_identity")
					or interface_info.get("identity", f"opt{ikeid}")
				)

				gateway_ip = _get_phase2_gateway_ip(phase2, tunnel_data)

				sanitized_gateway_name = _sanitize_gateway_name(tunnel_name)
				if not sanitized_gateway_name:
					sanitized_gateway_name = f"gateway{ikeid}"

				gateway = Gateway(gateway=gateway_ip)
				gateway.disabled = False
				gateway.interface_identity = interface_identity
				gateway.interface_assigned = interface_assigned
				gateway.interface_device = interface_device
				gateway.ipprotocol = "inet"
				gateway.name = sanitized_gateway_name
				gateway.monitor_disable = False
				gateway.action_disable = False
				gateway.nonlocalgateway = False
				gateway["dpinger_dont_add_static_route"] = False
				gateway["force_down"] = False
				gateway["_show_advanced"] = True

				result = child.call(add_gateway.sync, body=gateway)
				if _is_bad_gateway_result(result):
					raise RuntimeError(
						f"Gateway creation failed for '{sanitized_gateway_name}' on '{device_name}'"
					)

				remote_firewall_name = _get_remote_firewall_name(tunnel_name, tunnel_data)
				if remote_firewall_name:
					groups_to_gateways[remote_firewall_name].append(sanitized_gateway_name)
				else:
					logging.warning(
						"Skipping gateway group assignment for tunnel '%s' on '%s': missing remote firewall",
						tunnel_name,
						device_name,
					)

				logging.info(
					"Created gateway '%s' (%s) on '%s' via %s",
					sanitized_gateway_name,
					gateway_ip,
					device_name,
					interface_device,
				)

			for remote_firewall_name, gateway_names in groups_to_gateways.items():
				group_name = _make_gateway_group_name(remote_firewall_name)
				gateway_priority = [
					GatewayGroupPriority(
						gateway=gateway_name,
						priority="1",
						vaddress="address",
					)
					for gateway_name in sorted(set(gateway_names))
				]

				gateway_group = GatewayGroup(name=group_name)
				gateway_group.trigger = "down"
				gateway_group.gateway_priority = gateway_priority
				print(gateway_group)
				group_result = child.call(add_gateway_group.sync, body=gateway_group)
				logging.info(group_result)
				if _is_bad_gateway_result(group_result):
					raise RuntimeError(
						f"Gateway group creation failed for '{group_name}' on '{device_name}'"
					)
				if hasattr(group_result, "to_dict"):
					logging.info(
						"Gateway group '%s' API response on '%s': %s",
						group_name,
						device_name,
						group_result.to_dict(),
					)
				else:
					logging.info(
						"Gateway group '%s' API response on '%s': %s",
						group_name,
						device_name,
						group_result,
					)
	
				logging.info(
					"Created gateway group '%s' with %d gateway(s) on '%s'",
					group_name,
					len(gateway_priority),
					device_name,
				)

		except Exception as e:
			raise
