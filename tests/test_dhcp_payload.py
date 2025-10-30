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
    ]

    for payload, expected in samples:
        parsed = psh.parse_payload(payload)
        assert parsed == expected


def test_parse_payload_returns_none_for_unexpected_format():
    assert psh.parse_payload("dhcp,info dhcp1 something unexpected") is None
