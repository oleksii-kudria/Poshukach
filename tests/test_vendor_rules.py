import pathlib
import sys

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import psh  # type: ignore  # noqa: E402

device_matches_vendor_rules = psh.device_matches_vendor_rules
load_device_rules = psh.load_device_rules


def _load_config(name: str):
    path = pathlib.Path("configs") / name
    return load_device_rules(path)


def _tp_link_row(name: str, mac: str, vendor: str = "TP-Link Systems Inc", vendor_class: str = ""):
    return {
        "name": name,
        "mac": mac,
        "vendor": vendor,
        "vendorClass": vendor_class,
    }


def test_tp_link_router_matches_network_vendor_rules():
    network_config = _load_config("device_network.yml")
    row = _tp_link_row(
        name="Archer C54",
        mac="AA:BB:CC:00:11:22",
        vendor_class="TP-LINK Router",
    )

    assert device_matches_vendor_rules(
        row,
        network_config.vendor_rules,
        config_label=network_config.label or "device_network.yml",
        log=False,
    )


def test_tp_link_adapter_is_excluded_from_network_and_ignore_by_vendor_rules():
    network_config = _load_config("device_network.yml")
    ignore_config = _load_config("device_ignore.yml")
    adapter_row = _tp_link_row(
        name="DESKTOP-123ASD",
        mac="3C:64:CF:55:26:0C",
        vendor_class="TP-Link Wireless Adapter",
    )

    assert not device_matches_vendor_rules(
        adapter_row,
        network_config.vendor_rules,
        config_label=network_config.label or "device_network.yml",
        log=False,
    )

    assert not device_matches_vendor_rules(
        adapter_row,
        ignore_config.vendor_rules,
        config_label=ignore_config.label or "device_ignore.yml",
        log=False,
    )
