# Import libraries for configuration, API interaction, and network calculations
import logging
import sys

# Import configuration and setup modules
from src.config import parse_args, load_config, build_settings
from src.tunnels import collect_tags, build_tag_interface_map, build_ipsec_tunnels, build_tunnel_calls, build_tunnel_index
from src.ipsec import build_ipsec_calls
from src.devices import build_device_children, apply_tunnels_to_devices, turn_on_ipsec_tunnels, apply_changes_to_all_devices

from src.helper_funcs import RequestClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def main() -> None:
    """Main function to orchestrate the workflow of loading configuration,
    building tunnels, and applying them to devices via the API.
    """
    try:
        args = parse_args()
        
        if args.dry_run:
            logging.info("=" * 60)
            logging.info("DRY RUN MODE - No changes will be made")
            logging.info("=" * 60)
        
        # Load and validate configuration
        data = load_config(args.file)
        settings = build_settings(data)

        # Build tunnel configurations
        tags = collect_tags(data)
        tagstointerfaces = build_tag_interface_map(data, tags)

        ipsectunnels = build_ipsec_tunnels(
            tagstointerfaces,
            data["tunnels_network"],
            data["hint_prefix"],
        )
        
        ipsectunnelsbyfirewall = build_tunnel_calls(ipsectunnels, data["firewalls"])
        tunnel_index = build_tunnel_index(ipsectunnelsbyfirewall)
        ipsectunnelcalls, tunnel_index = build_ipsec_calls(
            ipsectunnelsbyfirewall,
            data["ipsec"]["ike"],
            tunnel_index
        )

        if args.dry_run:
            logging.info("Configuration built successfully")
            logging.info(f"Total tunnels to be created: {len(ipsectunnels)}")
            for fw, tunnels in ipsectunnelsbyfirewall.items():
                logging.info(f"  {fw}: {len(tunnels)} tunnels")
            logging.info("Dry run complete - exiting without making API calls")
            return

        # Initialize API client and authenticate
        logging.info("Initializing API client...")
        sessionClient = RequestClient(controller_url=settings.CONTROLLER_URL)
        
        if not sessionClient.login(settings.USER, settings.PASSWORD):
            logging.error("Login failed")
            sys.exit(1)
        
        logging.info("Successfully authenticated")

        # Build device clients and apply configurations
        device_children = build_device_children(sessionClient)
        apply_tunnels_to_devices(device_children, ipsectunnelcalls, tunnel_index, args.dry_run)
        turn_on_ipsec_tunnels(device_children, args.dry_run)
        apply_changes_to_all_devices(device_children, args.dry_run)

        # Stop the refresh timer to exit cleanly
        sessionClient.stop()
        
        logging.info("=" * 60)
        logging.info("Configuration completed successfully")
        logging.info("=" * 60)
        
    except KeyboardInterrupt:
        logging.warning("\nOperation cancelled by user")
        sys.exit(130)
    except Exception as e:
        logging.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()