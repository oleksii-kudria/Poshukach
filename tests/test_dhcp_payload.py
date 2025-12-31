import pathlib
import sys

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import psh  # type: ignore  # noqa: E402


def test_parse_payload_supports_various_server_names():
    samples = [
        (
            "dhcp,info defconf assigned 192.168.88.243 to 4C:D5:77:7D:94:47",
            ("192.168.88.243", "4C:D5:77:7D:94:47", "unknown"),
        ),
        (
            "dhcp,info dhcp1 assigned 192.168.1.60 for EE:3c:e7:da:8e:b4",
            ("192.168.1.60", "EE:3C:E7:DA:8E:B4", "unknown"),
        ),
        (
            "dhcp,info LAN_dhcp assigned 10.10.0.100 for 12:34:56:78:9A:BC workstation-42",
            ("10.10.0.100", "12:34:56:78:9A:BC", "workstation-42"),
        ),
        (
            "dhcp,info wifi_dhcp assigned 192.168.10.22 to 00:11:22:33:44:55   tablet  ",
            ("192.168.10.22", "00:11:22:33:44:55", "tablet"),
        ),
        (
            "dhcp,info верхній ряд DHCP assigned 192.168.55.159 for EE:33:52:11:49:91",
            ("192.168.55.159", "EE:33:52:11:49:91", "unknown"),
        ),
        (
            "dhcp,info нижній ряд DHCP assigned 192.168.99.240 for 00:22:44:91:95:52 Ariba",
            ("192.168.99.240", "00:22:44:91:95:52", "Ariba"),
        ),
        (
            "dhcp,info Home DHCP assigned 192.168.10.11 for 7E:44:02:44:6D:44",
            ("192.168.10.11", "7E:44:02:44:6D:44", "unknown"),
        ),
    ]

    for payload, expected in samples:
        parsed = psh.parse_payload(payload)
        assert parsed == expected


def test_parse_payload_supports_prefixed_messages():
    samples = [
        (
            "dhcp,info 3CC_: server-guest assigned 192.168.1.108 for FF:EE:DD:CC:BB:AA S24-FE",
            ("192.168.1.108", "FF:EE:DD:CC:BB:AA", "S24-FE"),
        ),
        (
            "dhcp,info myTag: dhcp1 assigned 10.0.0.15 to 00-11-22-33-44-55",
            ("10.0.0.15", "00:11:22:33:44:55", "unknown"),
        ),
    ]

    for payload, expected in samples:
        parsed = psh.parse_payload(payload)
        assert parsed == expected


def test_parse_payload_returns_none_for_unexpected_format():
    assert psh.parse_payload("dhcp,info dhcp1 something unexpected") is None


def test_parse_payload_supports_cef_messages():
    payload = (
        "2025-11-01T01:10:54.868+0200 1MB CEF:0|MikroTik|RB2011UAS|7.19.4 (stable)|16|dhcp,info|Low|"
        "dvchost=1MB dvc=10.10.10.225 msg=dhcp1 assigned 192.168.1.14 for AA:44:33:00:77:CC POCO"
    )
    parsed = psh.parse_payload(payload)
    assert parsed == ("192.168.1.14", "AA:44:33:00:77:CC", "POCO")


def test_parse_payload_normalises_mac_and_name_in_cef_msg():
    payload = (
        "CEF:0|Vendor|Product|1.0|100|dhcp,info|Low|msg=dhcp,info LAN_dhcp assigned 10.10.0.100 for 12-34-56-78-9A-BC \""
        "12-34-56-78-9A-BC\""
    )
    parsed = psh.parse_payload(payload)
    assert parsed == ("10.10.0.100", "12:34:56:78:9A:BC", "unknown")


def test_should_skip_cef_client_message_detects_exact_pattern():
    payload = (
        "2025-11-08T03:12:43.611+0200 1MB CEF:0|MikroTik|RB2011UAS|7.19.4 (stable)|16|dhcp,info|Low|"
        "dvcchost=1MB dvc=10.10.10.225 msg=dhcp-client on ether1 got IP address 192.168.1.22"
    )
    assert psh.should_skip_cef_client_message(payload) is True


def test_should_skip_cef_client_message_does_not_skip_assignment():
    payload = (
        "2025-11-01T01:10:54.868+0200 1MB CEF:0|MikroTik|RB2011UAS|7.19.4 (stable)|16|dhcp,info|Low|"
        "dvchost=1MB dvc=10.10.10.225 msg=dhcp1 assigned 192.168.1.14 for AA:44:33:00:77:CC POCO"
    )
    assert psh.should_skip_cef_client_message(payload) is False


def test_should_skip_standard_client_body_matches_exact_pattern():
    body = "dhcp-client on ether2 got IP address 192.168.1.223"
    assert psh.should_skip_standard_client_body(body) is True


def test_should_skip_standard_client_body_uses_substring_detection():
    body = "Some dhcp-client on ether3 log that later got IP address 10.0.0.5"
    assert psh.should_skip_standard_client_body(body) is True


def test_parse_payload_supports_dnsmasq_dhcpack():
    payload = (
        "<30>Dec 14 06:37:13 UDMD UDMD dnsmasq-dhcp[3896]: DHCPACK(br0) "
        "192.168.2.154 84:78:48:c0:28:92 T1-UPS-2"
    )

    parsed = psh.parse_payload(payload)

    assert parsed == ("192.168.2.154", "84:78:48:C0:28:92", "T1-UPS-2")


def test_parse_payload_sets_unknown_name_for_dnsmasq_without_hostname():
    payload = (
        "<30>Dec 14 06:37:04 UDMD UDMD dnsmasq-dhcp[3896]: DHCPACK(br0) "
        "192.168.2.200 60:22:32:21:22:19"
    )

    parsed = psh.parse_payload(payload)

    assert parsed == ("192.168.2.200", "60:22:32:21:22:19", "unknown")
