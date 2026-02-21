"""Device interaction and API calls module."""

import logging
from typing import Dict, Any, List

from pfapi.api.mim import get_controlled_devices
from pfapi.api.interfaces import get_interfaces, get_interface_descriptors, add_interface
from pfapi.api.vpn import set_ip_sec_phase_1, set_ip_sec_phase_2
from pfapi.api.system import apply_dirty_config
from pfapi.models import Interface, ApplyDirtyConfigRequest


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


def apply_tunnels_to_devices(
    device_children: Dict[str, Any],
    ipsectunnelcalls: Dict[str, List[Any]],
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
