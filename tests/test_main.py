from types import SimpleNamespace
from unittest.mock import MagicMock

import main


def test_main_dry_run_skips_api_client_creation(monkeypatch) -> None:
    monkeypatch.setattr(main, "parse_args", lambda: SimpleNamespace(file="config.yaml", dry_run=True))
    monkeypatch.setattr(
        main,
        "load_config",
        lambda _: {
            "api_server": "10.0.0.1",
            "api_port": 8443,
            "firewalls": [{"name": "fw1"}],
            "tunnels_network": "10.0.0.0/24",
            "hint_prefix": "vpn",
            "ipsec": {"ike": "ikev2"},
        },
    )
    monkeypatch.setattr(main, "build_settings", lambda _: SimpleNamespace(CONTROLLER_URL="https://x", USER="u", PASSWORD="p"))
    monkeypatch.setattr(main, "build_tag_interface_map", lambda _: {"wan": []})
    monkeypatch.setattr(main, "build_ipsec_tunnels", lambda *_: [])
    monkeypatch.setattr(main, "build_tunnel_calls", lambda *_: {"fw1": []})
    monkeypatch.setattr(main, "build_tunnel_index", lambda _: {"fw1": {}})
    monkeypatch.setattr(main, "build_ipsec_calls", lambda *_: ({"fw1": []}, {"fw1": {}}))

    request_client_ctor = MagicMock()
    monkeypatch.setattr(main, "RequestClient", request_client_ctor)

    main.main()

    request_client_ctor.assert_not_called()
