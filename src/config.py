"""Configuration loading and validation module."""

import yaml
import argparse
import logging
from typing import Dict, Any

from src.helper_funcs import get_settings


def parse_args() -> argparse.Namespace:
    """
    Parses command line arguments.
    
    Returns:
        argparse.Namespace: Parsed command line arguments.
    """
    parser = argparse.ArgumentParser(
        description='Configure pfSense SD-WAN IPSec tunnels based on YAML configuration'
    )
    parser.add_argument(
        '--file', 
        type=str, 
        default='pfhq.yaml', 
        help='Path to the YAML configuration file'
    )
    parser.add_argument(
        '--state_file', 
        type=str, 
        default='pfhq.data', 
        help='Path to the state file'
    )
    parser.add_argument(
        '--dry_run', 
        action='store_true', 
        help='Perform a dry run without making API calls'
    )
    return parser.parse_args()


def load_config(yaml_file: str) -> Dict[str, Any]:
    """Loads the YAML configuration file and returns it as a Python dictionary.
    
    Args:
        yaml_file: The path to the YAML configuration file.
        
    Returns:
        The loaded configuration data as a Python dictionary.
        
    Raises:
        FileNotFoundError: If the YAML file doesn't exist.
        yaml.YAMLError: If the YAML file is malformed.
    """
    try:
        logging.info(f"Loading configuration from {yaml_file}")
        with open(yaml_file, 'r') as file:
            config = yaml.safe_load(file)
            validate_config(config)
            return config
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {yaml_file}")
        raise
    except yaml.YAMLError as e:
        logging.error(f"Error parsing YAML file: {e}")
        raise


def validate_config(config: Dict[str, Any]) -> None:
    """Validates the configuration structure.
    
    Args:
        config: The loaded configuration data.
        
    Raises:
        ValueError: If required fields are missing.
    """
    required_fields = ['api_server', 'firewalls', 'tunnels_network', 'hint_prefix', 'ipsec']
    missing_fields = [field for field in required_fields if field not in config]
    
    if missing_fields:
        raise ValueError(f"Missing required configuration fields: {', '.join(missing_fields)}")
    
    if not config['firewalls']:
        raise ValueError("At least one firewall must be defined")
    
    logging.info("Configuration validation passed")


def build_settings(data: Dict[str, Any]):
    """Builds the settings object for API interaction based on the loaded YAML data.
    
    Args:
        data: The loaded configuration data from the YAML file.
        
    Returns:
        A settings object configured for API interaction.
    """
    # If USER environment variable is not set, it defaults to admin.
    # CONTROLLER_URL cannot have a trailing slash, otherwise the API calls will fail.
    settings = get_settings()
    settings.CONTROLLER_URL = f"https://{data['api_server']}:8443"
    logging.info(f"Configured controller URL: {settings.CONTROLLER_URL}")
    return settings
