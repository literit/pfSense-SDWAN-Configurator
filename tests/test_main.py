from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import main


def test_main_dry_run_skips_api_client_creation(monkeypatch) -> None:
    monkeypatch.setattr(
        main,
        "parse_args",
        lambda: SimpleNamespace(file="config.yaml", state_file="state.pkl", dry_run=True),
    )
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


def test_main_dry_run_loads_existing_state_file(monkeypatch, tmp_path) -> None:
    state_file = tmp_path / "state.pkl"
    state_file.write_bytes(b"state")

    monkeypatch.setattr(
        main,
        "parse_args",
        lambda: SimpleNamespace(file="config.yaml", state_file=str(state_file), dry_run=True),
    )
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

    allocator = SimpleNamespace(network_cidr="10.0.0.0/24")
    import_db_mock = MagicMock(return_value=allocator)
    monkeypatch.setattr(main.TunnelIpAllocator, "import_db", import_db_mock)
    monkeypatch.setattr(main.TunnelIpAllocator, "init_db", MagicMock())

    build_ipsec_tunnels_mock = MagicMock(return_value=[])
    monkeypatch.setattr(main, "build_ipsec_tunnels", build_ipsec_tunnels_mock)
    monkeypatch.setattr(main, "build_tunnel_calls", lambda *_: {"fw1": []})
    monkeypatch.setattr(main, "build_tunnel_index", lambda _: {"fw1": {}})
    monkeypatch.setattr(main, "build_ipsec_calls", lambda *_: ({"fw1": []}, {"fw1": {}}))

    main.main()

    import_db_mock.assert_called_once_with(str(state_file))
    build_ipsec_tunnels_mock.assert_called_once_with({"wan": []}, "10.0.0.0/24", "vpn", allocator)


def test_main_state_file_network_mismatch_exits(monkeypatch, tmp_path) -> None:
    state_file = tmp_path / "state.pkl"
    state_file.write_bytes(b"state")

    monkeypatch.setattr(
        main,
        "parse_args",
        lambda: SimpleNamespace(file="config.yaml", state_file=str(state_file), dry_run=True),
    )
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
    monkeypatch.setattr(
        main.TunnelIpAllocator,
        "import_db",
        MagicMock(return_value=SimpleNamespace(network_cidr="10.1.0.0/24")),
    )

    with pytest.raises(SystemExit) as exc:
        main.main()

    assert exc.value.code == 1
