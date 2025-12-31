#!/usr/bin/env python3
"""CLI utilities for working with Poshukach datasets.

The script provides two main commands:

``dhcp-aggregate``
    Aggregate DHCP log files into ``data/interim/dhcp.csv``. The command
    reads every CSV file in ``data/raw/dhcp`` (excluding ``*.example.csv``),
    validates their headers and then aggregates the records by MAC
    address. The resulting dataset is written to
    ``data/interim/dhcp.csv`` with the following columns::

        source,ip,mac,vendor,name,firstDate,lastDate,firstDateEpoch,
        lastDateEpoch,count,randomized,dateList

    The ``source``/``ip``/``name`` fields correspond to the most recent
    log entry for the MAC address, timestamps are reported both as the
    original epoch values and in human readable form (UTC), and
    ``randomized`` indicates whether the MAC address uses a locally
    administered prefix.

``mac-scan``
    Scan ``data/raw/av-mac`` for MAC addresses in arbitrary CSV files,
    normalise them to ``XX:XX:XX:XX:XX:XX`` format and write the unique
    results into ``data/interim/mac.csv`` together with the file name
    where the address was first seen.

``rds``
    Aggregate Remote Desktop Services discovery files from
    ``data/raw/rds`` (excluding ``*.example.csv``). The command parses
    semicolon-delimited CSV files, normalises MAC addresses and
    aggregates entries per MAC. The resulting dataset is written to
    ``data/interim/rds.csv`` with the same columns as the DHCP
    aggregation: source, ip, mac, vendor, name, firstDate, lastDate,
    firstDateEpoch, lastDateEpoch, count, randomized, dateList.
"""

from __future__ import annotations

import argparse
import csv
import io
import re
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from zoneinfo import ZoneInfo
from pathlib import Path
from typing import DefaultDict, Dict, Iterable, List, Pattern, Set, Tuple

import yaml

MAC_PATTERN = re.compile(r"""(?i)\b([0-9a-f]{2}([-:]))(?:[0-9a-f]{2}\2){4}[0-9a-f]{2}\b""")

CONSOLE_SEPARATOR = "--------------------------------------------"

DeviceRule = Tuple[str, List[object]]


def set_max_csv_field_size() -> None:
    """Increase the CSV field size limit to handle large aggregated fields."""

    max_int = sys.maxsize
    while max_int > 0:
        try:
            csv.field_size_limit(max_int)
            break
        except OverflowError:
            max_int //= 10
    else:
        raise OverflowError("Unable to set CSV field size limit")


@dataclass
class VendorPattern:
    value: str
    is_regex: bool = False
    compiled: Pattern[str] | None = None


def extract_oui_prefix(mac: str) -> str:
    normalised = normalise_oui(mac or "")
    if len(normalised) < 6:
        return ""
    prefix = normalised[:6]
    return ":".join(prefix[i : i + 2] for i in range(0, 6, 2))


@dataclass
class MatchCheckResult:
    hit: bool
    detail: str
    available: bool


@dataclass
class VendorRequireConfig:
    name_contains: List[str] = field(default_factory=list)
    vendor_class_contains: List[str] = field(default_factory=list)
    vendor_class_regex: List[Pattern[str]] = field(default_factory=list)
    oui_prefixes: List[str] = field(default_factory=list)

    def has_rules(self) -> bool:
        return any(
            (
                self.name_contains,
                self.vendor_class_contains,
                self.vendor_class_regex,
                self.oui_prefixes,
            )
        )


@dataclass
class VendorExceptConfig:
    name_contains: List[str] = field(default_factory=list)
    name_regex: List[Pattern[str]] = field(default_factory=list)
    oui_prefixes: List[str] = field(default_factory=list)

    def has_rules(self) -> bool:
        return any((self.name_contains, self.name_regex, self.oui_prefixes))


@dataclass
class VendorRule:
    patterns: List[VendorPattern]
    require: VendorRequireConfig | None = None
    except_: VendorExceptConfig | None = None


@dataclass
class DeviceFilterConfig:
    name_rules: List[DeviceRule] = field(default_factory=list)
    vendor_rules: List[VendorRule] = field(default_factory=list)
    label: str = ""


@dataclass
class DhcpLineStats:
    prefixed_processed: int = 0
    skipped_client_rows: int = 0
    dnsmasq_processed: int = 0
    dnsmasq_skipped: int = 0
    unifi_processed: int = 0
    unifi_skipped: int = 0


@dataclass
class DhcpColumnMapping:
    source_index: int
    mac_index: int
    payload_index: int
    time_index: int
    time_column_name: str
    use_log_source_time: bool
    payload_column_name: str
    is_alternative_mapping: bool


@dataclass
class VendorRuleStats:
    config_label: str
    applied: int = 0
    skipped_by_except: int = 0
    skipped_by_require: int = 0

    def summary_line(self) -> str:
        skipped_total = self.skipped_by_except + self.skipped_by_require
        return (
            f"🔧 Підсумок правил vendor ({self.config_label}): "
            f"застосовано={self.applied}, пропущено={skipped_total} "
            f"(except={self.skipped_by_except}, require={self.skipped_by_require})"
        )


def ensure_string_list(value: object, *, config_label: str) -> List[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"⚠️ Некоректна структура {config_label}, фільтрацію вимкнено")
    return [item for item in value if item]


def is_vendor_pattern_regex(pattern: str) -> bool:
    if "(?" in pattern:
        return True

    regex_specials = set("^$*+?{}[]|\\")
    return any(char in regex_specials for char in pattern)


def build_vendor_pattern(pattern: str, *, config_label: str) -> VendorPattern:
    cleaned = (pattern or "").strip()
    if not cleaned:
        return VendorPattern(value="")

    if is_vendor_pattern_regex(cleaned):
        try:
            compiled = re.compile(cleaned, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"⚠️ Некоректний regex у {config_label}: {exc}") from exc
        return VendorPattern(value=cleaned, is_regex=True, compiled=compiled)

    return VendorPattern(value=normalize_vendor(cleaned))


def parse_vendor_require_config(value: object, config_label: str) -> VendorRequireConfig | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError(f"⚠️ Некоректна структура {config_label}, фільтрацію вимкнено")

    require = VendorRequireConfig()

    name_contains = ensure_string_list(value.get("name_contains"), config_label=config_label)
    require.name_contains = [item.lower() for item in name_contains]

    vendor_class_contains = ensure_string_list(value.get("vendor_class_contains"), config_label=config_label)
    require.vendor_class_contains = [item.lower() for item in vendor_class_contains]

    vendor_class_regex_raw = ensure_string_list(value.get("vendor_class_regex"), config_label=config_label)
    for pattern in vendor_class_regex_raw:
        try:
            require.vendor_class_regex.append(re.compile(pattern, re.IGNORECASE))
        except re.error as exc:
            raise ValueError(f"⚠️ Некоректний regex у {config_label}: {exc}") from exc

    oui_prefixes = ensure_string_list(value.get("oui_prefixes"), config_label=config_label)
    require.oui_prefixes = [item.upper() for item in oui_prefixes]

    return require if require.has_rules() else None


def parse_vendor_except_config(value: object, config_label: str) -> VendorExceptConfig | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError(f"⚠️ Некоректна структура {config_label}, фільтрацію вимкнено")

    except_config = VendorExceptConfig()

    name_contains = ensure_string_list(value.get("name_contains"), config_label=config_label)
    except_config.name_contains = [item.lower() for item in name_contains]

    name_regex_raw = ensure_string_list(value.get("name_regex"), config_label=config_label)
    for pattern in name_regex_raw:
        try:
            except_config.name_regex.append(re.compile(pattern, re.IGNORECASE))
        except re.error as exc:
            raise ValueError(f"⚠️ Некоректний regex у {config_label}: {exc}") from exc

    oui_prefixes = ensure_string_list(value.get("oui_prefixes"), config_label=config_label)
    except_config.oui_prefixes = [item.upper() for item in oui_prefixes]

    return except_config if except_config.has_rules() else None


def load_device_rules(config_path: Path) -> DeviceFilterConfig:
    if not config_path.exists():
        return DeviceFilterConfig(label=config_path.name)

    config_label = config_path.as_posix()

    try:
        with config_path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except OSError as exc:
        print(f"⚠️ Неможливо прочитати {config_label}: {exc}")
        return DeviceFilterConfig(label=config_path.name)
    except yaml.YAMLError as exc:
        print(f"⚠️ Неможливо розпарсити {config_label}: {exc}")
        return DeviceFilterConfig(label=config_path.name)

    if not isinstance(data, dict):
        print(f"⚠️ Некоректна структура {config_label}, фільтрацію вимкнено")
        return DeviceFilterConfig(label=config_path.name)

    rules_data = data.get("rules")
    if rules_data is None:
        return DeviceFilterConfig()

    if not isinstance(rules_data, list):
        print(f"⚠️ Некоректна структура {config_label}, фільтрацію вимкнено")
        return DeviceFilterConfig()

    compiled_rules: List[DeviceRule] = []
    vendor_rules: List[VendorRule] = []
    valid_modes = {"prefix", "contains", "regex", "vendor"}

    for entry in rules_data:
        if not isinstance(entry, dict):
            print(f"⚠️ Некоректна структура {config_label}, фільтрацію вимкнено")
            return DeviceFilterConfig(label=config_path.name)

        mode = entry.get("mode")
        patterns = entry.get("patterns")

        if mode not in valid_modes or not isinstance(patterns, list):
            print(f"⚠️ Некоректна структура {config_label}, фільтрацію вимкнено")
            return DeviceFilterConfig(label=config_path.name)

        if not all(isinstance(item, str) for item in patterns):
            print(f"⚠️ Некоректна структура {config_label}, фільтрацію вимкнено")
            return DeviceFilterConfig(label=config_path.name)

        if mode in {"prefix", "contains"}:
            compiled_rules.append((mode, [pattern.lower() for pattern in patterns]))
        elif mode == "regex":
            try:
                compiled = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
            except re.error as exc:
                print(f"⚠️ Некоректний regex у {config_label}: {exc}")
                return DeviceFilterConfig(label=config_path.name)

            compiled_rules.append((mode, compiled))
        else:  # mode == "vendor"
            try:
                vendor_rules.append(
                    VendorRule(
                        patterns=[
                            build_vendor_pattern(pattern, config_label=config_label)
                            for pattern in patterns
                        ],
                        require=parse_vendor_require_config(entry.get("require"), config_label),
                        except_=parse_vendor_except_config(entry.get("except"), config_label),
                    )
                )
            except ValueError as exc:
                print(exc)
                return DeviceFilterConfig(label=config_path.name)

    return DeviceFilterConfig(name_rules=compiled_rules, vendor_rules=vendor_rules, label=config_path.name)


def load_device_ignore_rules(config_path: Path) -> DeviceFilterConfig:
    return load_device_rules(config_path)


def matches_device_rules(name: str, rules: List[DeviceRule]) -> bool:
    if not rules:
        return False

    value = name or ""
    lowered = value.lower()

    for mode, patterns in rules:
        if mode == "prefix":
            if any(lowered.startswith(pattern) for pattern in patterns):
                return True
        elif mode == "contains":
            if any(pattern in lowered for pattern in patterns):
                return True
        elif mode == "regex":
            for pattern in patterns:
                if pattern.search(value):
                    return True

    return False


def normalize_vendor(value: str) -> str:
    value = (value or "").strip()
    if value:
        value = re.sub(r"[\s]+", " ", value)
        value = re.sub(r"[\s,.;]+$", "", value)
    return (value or "").lower()


def match_vendor_patterns(vendor: str, patterns: List[VendorPattern]) -> bool:
    if not patterns:
        return False

    vendor_value = vendor or ""
    vendor_norm = normalize_vendor(vendor_value)

    for pattern in patterns:
        if pattern.is_regex:
            if pattern.compiled and pattern.compiled.search(vendor_value):
                return True
        else:
            if pattern.value and pattern.value in vendor_norm:
                return True

    return False


def require_hit(row: Dict[str, str], require_cfg: VendorRequireConfig | None) -> MatchCheckResult:
    if require_cfg is None or not require_cfg.has_rules():
        return MatchCheckResult(True, "n/a", False)

    name_value = (row.get("name") or "").strip()
    lowered_name = name_value.lower()
    for pattern in require_cfg.name_contains:
        if pattern and pattern in lowered_name:
            return MatchCheckResult(True, f'name_contains → "{pattern}"', True)

    vendor_class_value = (row.get("vendorClass") or "").strip()
    lowered_vendor_class = vendor_class_value.lower()
    for pattern in require_cfg.vendor_class_contains:
        if pattern and pattern in lowered_vendor_class:
            return MatchCheckResult(True, f'vendor_class_contains → "{pattern}"', True)

    for compiled in require_cfg.vendor_class_regex:
        if compiled.search(vendor_class_value):
            return MatchCheckResult(True, f'vendor_class_regex → "{compiled.pattern}"', True)

    mac_value = (row.get("mac") or "").strip()
    prefix = extract_oui_prefix(mac_value)
    for pattern in require_cfg.oui_prefixes:
        if pattern and prefix == pattern:
            return MatchCheckResult(True, f'oui_prefixes → "{pattern}"', True)

    return MatchCheckResult(False, "none", True)


def except_hit(row: Dict[str, str], except_cfg: VendorExceptConfig | None) -> MatchCheckResult:
    if except_cfg is None or not except_cfg.has_rules():
        return MatchCheckResult(False, "n/a", False)

    name_value = (row.get("name") or "").strip()
    lowered_name = name_value.lower()
    for pattern in except_cfg.name_contains:
        if pattern and pattern in lowered_name:
            return MatchCheckResult(True, f'name_contains → "{pattern}"', True)

    for compiled in except_cfg.name_regex:
        if compiled.search(name_value):
            return MatchCheckResult(True, f'name_regex → "{compiled.pattern}"', True)

    mac_value = (row.get("mac") or "").strip()
    prefix = extract_oui_prefix(mac_value)
    for pattern in except_cfg.oui_prefixes:
        if pattern and prefix == pattern:
            return MatchCheckResult(True, f'oui_prefixes → "{pattern}"', True)

    return MatchCheckResult(False, "none", True)


def log_vendor_rule_event(
    *,
    action: str,
    config_label: str,
    vendor_value: str,
    require_result: MatchCheckResult,
    except_result: MatchCheckResult,
) -> None:
    suffix = " with require/except" if (require_result.available or except_result.available) else ""

    print(f"🔧 vendor-rule: {action}{suffix} ({config_label})")
    print(f"   • matched vendor: {vendor_value or '<empty>'}")
    require_detail = require_result.detail if require_result.available else "n/a"
    except_detail = except_result.detail if except_result.available else "n/a"
    print(f"   • require hit: {require_detail}")
    print(f"   • except hit: {except_detail}")


def device_matches_vendor_rules(
    row: Dict[str, str],
    vendor_rules: List[VendorRule],
    *,
    config_label: str,
    stats: VendorRuleStats | None = None,
    log: bool = False,
) -> bool:
    vendor_value = (row.get("vendor") or "").strip()

    for rule in vendor_rules:
        if not match_vendor_patterns(vendor_value, rule.patterns):
            continue

        except_result = except_hit(row, rule.except_)
        if except_result.hit:
            if stats is not None:
                stats.skipped_by_except += 1
            if log:
                log_vendor_rule_event(
                    action="skipped by except",
                    config_label=config_label,
                    vendor_value=vendor_value,
                    require_result=require_hit(row, rule.require),
                    except_result=except_result,
                )
            continue

        require_result = require_hit(row, rule.require)
        if not require_result.hit:
            if stats is not None and require_result.available:
                stats.skipped_by_require += 1
            if log and require_result.available:
                log_vendor_rule_event(
                    action="skipped (require not satisfied)",
                    config_label=config_label,
                    vendor_value=vendor_value,
                    require_result=require_result,
                    except_result=except_result,
                )
            continue

        if log:
            log_vendor_rule_event(
                action="applied",
                config_label=config_label,
                vendor_value=vendor_value,
                require_result=require_result,
                except_result=except_result,
            )
        if stats is not None:
            stats.applied += 1
        return True

    return False


def cleanup_result_directory(result_dir: Path) -> None:
    print("🧹 Cleaning up result directory...")

    try:
        result_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"⚠️ Неможливо створити директорію data/result/: {exc}")
        return

    csv_files = list(result_dir.glob("*.csv"))
    files_to_remove: List[Path] = []
    skipped_count = 0

    for file_path in csv_files:
        if file_path.name.endswith(".example.csv"):
            skipped_count += 1
            continue
        files_to_remove.append(file_path)

    if not files_to_remove:
        if skipped_count:
            print(f"   • Пропущено {skipped_count} файл(и) (*.example.csv)")
        print("🧹 Немає файлів для очищення.")
        return

    deleted_count = 0
    failed_files: List[Tuple[Path, Exception]] = []

    for file_path in files_to_remove:
        try:
            file_path.unlink()
            deleted_count += 1
        except OSError as exc:
            failed_files.append((file_path, exc))

    if deleted_count:
        print(f"   • Видалено {deleted_count} файлів з data/result/")

    if skipped_count:
        print(f"   • Пропущено {skipped_count} файл(и) (*.example.csv)")

    for file_path, error in failed_files:
        try:
            relative_path = file_path.relative_to(result_dir)
        except ValueError:
            relative_path = file_path
        print(f"⚠️ Не вдалося видалити data/result/{relative_path}: {error}")

    if failed_files:
        print("⚠️ Очищення директорії завершено з попередженнями.")
    else:
        print("✅ Директорія очищена успішно.")


def normalise_device_name(value: str) -> str:
    value = (value or "").strip()
    if value:
        value = re.sub(r"\s+", " ", value)

    value = value or "unknown"
    return value.lower()


def move_name_duplicates(result_dir: Path) -> None:
    true_path = result_dir / "dhcp-true.csv"
    false_path = result_dir / "dhcp-false.csv"
    duplicate_path = result_dir / "dhcp-dublicate.csv"

    missing_sources: List[str] = []
    for path in (true_path, false_path):
        if path.exists():
            continue
        try:
            label = path.relative_to(result_dir.parent.parent).as_posix()
        except ValueError:
            label = path.as_posix()
        missing_sources.append(label)

    if missing_sources:
        formatted = ", ".join(sorted(set(missing_sources)))
        print(
            f"⚠️ Пропущено перевірку дублікатів за name: відсутні файли {formatted}"
        )
        return

    try:
        with true_path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            headers_true = reader.fieldnames or []
            if "name" not in headers_true:
                print(
                    "⚠️ Пропущено перевірку дублікатів за name: data/result/dhcp-true.csv не містить колонки 'name'"
                )
                return
            true_names = {
                normalise_device_name(row.get("name"))
                for row in reader
                if row is not None
            }
    except OSError as exc:
        print(f"⚠️ Неможливо прочитати data/result/dhcp-true.csv: {exc}")
        return

    try:
        with false_path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            headers_false = reader.fieldnames
            if not headers_false:
                print(
                    "⚠️ Пропущено перевірку дублікатів за name: data/result/dhcp-false.csv не містить заголовок"
                )
                return
            if "name" not in headers_false:
                print(
                    "⚠️ Пропущено перевірку дублікатів за name: data/result/dhcp-false.csv не містить колонки 'name'"
                )
                return
            false_rows = [row for row in reader if row is not None]
    except OSError as exc:
        print(f"⚠️ Неможливо прочитати data/result/dhcp-false.csv: {exc}")
        return

    duplicate_rows: List[Dict[str, str]] = []
    remaining_rows: List[Dict[str, str]] = []

    for row in false_rows:
        if normalise_device_name(row.get("name")) in true_names:
            duplicate_rows.append(row)
        else:
            remaining_rows.append(row)

    duplicate_count = len(duplicate_rows)

    if duplicate_count:
        write_header = True
        try:
            if duplicate_path.exists():
                write_header = duplicate_path.stat().st_size == 0
        except OSError:
            write_header = False

        try:
            with duplicate_path.open("a", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=headers_false)
                if write_header:
                    writer.writeheader()
                writer.writerows(duplicate_rows)
        except OSError as exc:
            print(f"⚠️ Неможливо оновити data/result/dhcp-dublicate.csv: {exc}")
            return

        try:
            with false_path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=headers_false)
                writer.writeheader()
                writer.writerows(remaining_rows)
        except OSError as exc:
            print(f"⚠️ Неможливо оновити data/result/dhcp-false.csv: {exc}")
            return

    print("🔁 Duplicate check by name:")
    print(f"   • Імен у dhcp-true.csv: {len(true_names)}")
    print(f"   • Перенесено з dhcp-false.csv до dhcp-dublicate.csv: {duplicate_count}")
    print(f"   • Залишилось у dhcp-false.csv: {len(remaining_rows)}")

    if duplicate_count:
        print(
            "📁 Оновлено: data/result/dhcp-false.csv, створено/оновлено: data/result/dhcp-dublicate.csv"
        )
    else:
        print("📁 Змін не виявлено: data/result/dhcp-false.csv")


MANDATORY_FIELDS: List[str] = [
    "logSourceIdentifier",
    "sourcMACAddress",
    "payloadAsUTF",
]
TIME_FIELDS: List[str] = ["deviceTime", "Log Source Time"]

PREFIXED_DHCP_PATTERN = re.compile(
    r"(?i)^dhcp,info\s+([^:]+):\s+(?P<body>.*)$"
)

DHCP_INFO_PREFIX_PATTERN = re.compile(r"(?i)^dhcp,info\s+")

DHCP_ASSIGNMENT_PATTERN = re.compile(
    r"^(?P<dhcpName>.+?)\s+assigned\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?:for|to)\s+"
    r"(?P<mac>[0-9A-Fa-f:.-]{2,})(?:\s+(?P<name>.+))?$",
    re.IGNORECASE,
)

DNSMASQ_DHCPACK_PATTERN = re.compile(
    r"DHCPACK\([^)]*\)\s+(?P<ip>[0-9.]+)\s+"
    r"(?P<mac>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})(?:\s+(?P<name>\S.+))?$",
    re.IGNORECASE,
)

CEF_KEY_PATTERN = re.compile(r"([A-Za-z0-9]+)=")
UNIFI_WIFI_CEF_TOKEN = "WiFi Client Connected"

STANDARD_CLIENT_PATTERN = re.compile(
    r"^dhcp-client\s+on\s+[^\s]+\s+got\s+IP\s+address\s+[0-9.]+$",
    re.IGNORECASE,
)

CEF_CLIENT_MESSAGE_PATTERN = re.compile(
    r"^dhcp-client\s+on\s+[^\s]+\s+got\s+IP\s+address\s+[0-9.]+$",
    re.IGNORECASE,
)



@dataclass
class MacAggregation:
    mac: str
    timestamps: List[Tuple[float, int, str]] = field(default_factory=list)
    last_source: str = ""
    last_ip: str = ""
    last_name: str = "unknown"
    last_seconds: float = float("-inf")
    first_seconds: float = float("inf")
    first_epoch: str | None = None
    last_epoch: str | None = None

    def add_entry(
        self,
        *,
        source: str,
        ip: str,
        name: str,
        epoch_raw: str,
        epoch_value: int,
        seconds: float,
    ) -> None:
        self.timestamps.append((seconds, epoch_value, epoch_raw))

        if seconds < self.first_seconds:
            self.first_seconds = seconds
            self.first_epoch = epoch_raw

        if seconds > self.last_seconds or (
            seconds == self.last_seconds and (self.last_epoch or "") < epoch_raw
        ):
            self.last_seconds = seconds
            self.last_epoch = epoch_raw
            self.last_source = source
            self.last_ip = ip
            self.last_name = name

    @property
    def count(self) -> int:
        return len(self.timestamps)

    def sorted_epoch_strings(self) -> List[str]:
        return [item[2] for item in sorted(self.timestamps, key=lambda data: (data[0], data[1]))]


@dataclass
class RdsAggregation:
    mac: str
    timestamps: List[int] = field(default_factory=list)
    last_source: str = ""
    last_ip: str = ""
    last_name: str = "unknown"
    first_epoch: int | None = None
    last_epoch: int | None = None

    def add_entry(self, *, source: str, ip: str, name: str, epoch: int) -> None:
        self.timestamps.append(epoch)

        if self.first_epoch is None or epoch < self.first_epoch:
            self.first_epoch = epoch

        if self.last_epoch is None or epoch > self.last_epoch:
            self.last_epoch = epoch
            self.last_source = source
            self.last_ip = ip
            self.last_name = name

    @property
    def count(self) -> int:
        return len(self.timestamps)

    def sorted_epochs(self) -> List[int]:
        return sorted(self.timestamps)


def iter_dhcp_csv_files(dhcp_dir: Path) -> Iterable[Path]:
    """Yield relevant CSV files from *dhcp_dir*.

    Files ending with ``.example.csv`` are ignored. Results are returned in
    alphabetical order for consistent output.
    """

    if not dhcp_dir.exists():
        return []

    files = sorted(
        path
        for path in dhcp_dir.glob("*.csv")
        if not path.name.endswith(".example.csv")
    )
    return files


def read_csv_header(csv_path: Path) -> List[str]:
    """Read and return the header columns from *csv_path*.

    The file is read using UTF-8 with BOM support. Only the first row is
    processed, with automatic delimiter detection via ``csv.Sniffer``.
    ``ValueError`` is raised when a header cannot be determined.
    """

    try:
        with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
            sample = handle.read(4096)
            if not sample:
                raise ValueError("Файл порожній або не містить заголовок.")

            handle.seek(0)
            try:
                dialect = csv.Sniffer().sniff(sample)
            except csv.Error:
                dialect = csv.excel

            reader = csv.reader(handle, dialect)
            try:
                header = next(reader)
            except StopIteration as exc:  # pragma: no cover - defensive
                raise ValueError("Файл порожній або не містить заголовок.") from exc
    except OSError as exc:  # pragma: no cover - filesystem error
        raise OSError(f"Помилка читання файлу: {exc}") from exc

    stripped = [column.strip() for column in header]
    if not any(stripped):
        raise ValueError("Файл порожній або не містить заголовок.")

    return stripped


def sniff_dialect(sample: str) -> csv.Dialect:
    try:
        return csv.Sniffer().sniff(sample)
    except csv.Error:
        return csv.excel


def parse_epoch(epoch_raw: str) -> Tuple[int, float]:
    value = int(epoch_raw)
    length = len(epoch_raw)
    if length >= 13:
        seconds = value / 1000
    elif length == 10:
        seconds = float(value)
    elif length > 10:
        seconds = value / 1000
    else:
        seconds = float(value)
    return value, seconds


KYIV_TZ = ZoneInfo("Europe/Kyiv")
UTC_TZ = ZoneInfo("UTC")
LOG_SOURCE_TIME_FORMAT = "%b %d, %Y, %I:%M:%S %p"


def epoch_to_str(seconds: float) -> str:
    dt = datetime.fromtimestamp(seconds, tz=UTC_TZ).astimezone(KYIV_TZ)
    return dt.strftime("%Y.%m.%d %H:%M")


def parse_log_source_time(value: str) -> Tuple[int, float]:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("Рядок містить порожні обовʼязкові поля")

    try:
        dt = datetime.strptime(cleaned, LOG_SOURCE_TIME_FORMAT)
    except ValueError as exc:
        raise ValueError(f"Некоректний формат Log Source Time: {value}") from exc

    dt = dt.replace(tzinfo=KYIV_TZ)
    seconds = dt.timestamp()
    milliseconds = int(round(seconds * 1000))
    normalized_seconds = milliseconds / 1000
    return milliseconds, normalized_seconds


def is_randomized_mac(mac: str) -> bool:
    first_octet = int(mac.split(":")[0], 16)
    return (first_octet & 0x02) != 0


def normalise_oui(value: str) -> str:
    return value.replace("-", "").replace(":", "").upper()


def load_oui_vendor_map(oui_path: Path) -> Dict[str, str]:
    if not oui_path.exists():
        print(
            "⚠️ Файл data/cache/oui.csv відсутній, значення vendor буде позначено як unknown."
        )
        return {}

    vendor_map: Dict[str, str] = {}

    try:
        with oui_path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                if row is None:
                    continue

                assignment = (row.get("Assignment") or "").strip()
                organization = (row.get("Organization Name") or "").strip()

                if not assignment or not organization:
                    continue

                vendor_map[normalise_oui(assignment)] = organization
    except csv.Error as exc:
        print(
            "⚠️ Неможливо розпарсити data/cache/oui.csv, значення vendor буде позначено як unknown."
        )
        print(str(exc))
        return {}
    except OSError as exc:
        print(
            "⚠️ Не вдалося прочитати data/cache/oui.csv, значення vendor буде позначено як unknown."
        )
        print(str(exc))
        return {}

    return vendor_map


def resolve_vendor(mac: str, vendor_map: Dict[str, str], randomized: bool) -> str:
    if randomized:
        return "unknown"

    oui = normalise_oui(mac)[:6]
    if not oui:
        return "unknown"

    return vendor_map.get(oui, "unknown")


def normalise_mac_address(mac: str) -> str:
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(cleaned) != 12:
        return mac.upper()
    pairs = [cleaned[i : i + 2] for i in range(0, 12, 2)]
    return ":".join(pair.upper() for pair in pairs)


def extract_standard_body(payload: str, *, stats: DhcpLineStats | None = None) -> str:
    cleaned = payload.strip()
    prefixed_match = PREFIXED_DHCP_PATTERN.match(cleaned)
    if prefixed_match:
        if stats:
            stats.prefixed_processed += 1
        body = prefixed_match.group("body").strip()
    else:
        body = cleaned

    body = DHCP_INFO_PREFIX_PATTERN.sub("", body, count=1).strip()
    return body


def should_skip_standard_client_body(body: str) -> bool:
    stripped = body.strip()
    if not stripped:
        return False

    if STANDARD_CLIENT_PATTERN.match(stripped):
        return True

    lowered = stripped.lower()
    return "dhcp-client on" in lowered and "got ip address" in lowered


def parse_standard_body(body: str) -> Tuple[str, str, str] | None:
    match = DHCP_ASSIGNMENT_PATTERN.match(body.strip())
    if not match:
        return None

    ip = match.group("ip")
    mac = normalise_mac_address(match.group("mac"))
    name = clean_device_name(match.group("name"), ip=ip, mac=mac)
    return ip, mac, name


def clean_device_name(name: str | None, *, ip: str, mac: str) -> str:
    if not name:
        return "unknown"

    cleaned = name.strip().strip('"').strip("'")
    if not cleaned:
        return "unknown"

    if cleaned.upper() == mac.upper() or cleaned == ip:
        return "unknown"

    normalised = normalise_mac_address(cleaned)
    if normalised == mac:
        return "unknown"

    return cleaned


def parse_standard_payload(payload: str) -> Tuple[str, str, str] | None:
    body = extract_standard_body(payload)
    return parse_standard_body(body)


def is_dnsmasq_dhcpack(payload: str) -> bool:
    lowered = payload.lower()
    return "dnsmasq-dhcp" in lowered and "dhcpack(" in lowered


def parse_dnsmasq_dhcpack(
    payload: str, *, stats: DhcpLineStats | None = None
) -> Tuple[str, str, str] | None:
    match = DNSMASQ_DHCPACK_PATTERN.search(payload)
    if not match:
        if stats:
            stats.dnsmasq_skipped += 1
        print(
            f"⚠️ Неможливо розпарсити dnsmasq DHCPACK рядок payloadAsUTF: {payload}"
        )
        return None

    ip = match.group("ip")
    mac = normalise_mac_address(match.group("mac"))
    name_raw = match.group("name")
    name = clean_device_name(name_raw, ip=ip, mac=mac)

    if stats:
        stats.dnsmasq_processed += 1

    return ip, mac, name


def parse_cef_extension(extension: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    if not extension:
        return result

    matches = list(CEF_KEY_PATTERN.finditer(extension))
    if not matches:
        return result

    for index, match in enumerate(matches):
        key = match.group(1).lower()
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(extension)
        value = extension[start:end].strip()
        result[key] = value
    return result


def extract_cef_extension(payload: str) -> str | None:
    try:
        _, _, _, _, _, _, _, extension = payload.split("|", 7)
    except ValueError:
        return None
    return extension


def extract_cef_msg(payload: str) -> str | None:
    extension = extract_cef_extension(payload)
    if extension is None:
        return None

    fields = parse_cef_extension(extension)
    msg = fields.get("msg")
    if not msg:
        msg_match = re.search(r"msg=([^=]+)", extension)
        if msg_match:
            msg = msg_match.group(1).strip()

    if not msg:
        return None

    return msg.strip()


def is_unifi_wifi_cef(payload: str) -> bool:
    return "CEF:" in payload and UNIFI_WIFI_CEF_TOKEN in payload


def parse_unifi_utc_time(utc_raw: str) -> str | None:
    cleaned = utc_raw.strip()
    if not cleaned:
        return None

    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC_TZ)

    kyiv_time = parsed.astimezone(KYIV_TZ)
    epoch_ms = int(kyiv_time.timestamp() * 1000)
    return str(epoch_ms)


def parse_unifi_wifi_cef(
    payload: str, *, stats: DhcpLineStats | None = None
) -> Tuple[str, str, str, str | None] | None:
    extension = extract_cef_extension(payload)
    if extension is None:
        if stats:
            stats.unifi_skipped += 1
        print(
            "⚠️ Неможливо розпарсити UniFi WiFi CEF рядок payloadAsUTF: "
            f"{payload}"
        )
        return None

    fields = parse_cef_extension(extension)
    ip = (fields.get("unificlientip") or "").strip()
    mac_raw = (fields.get("unificlientmac") or "").strip()
    name_raw = (fields.get("unificlienthostname") or "").strip()

    if not ip or not mac_raw:
        if stats:
            stats.unifi_skipped += 1
        print(
            "⚠️ Неможливо розпарсити UniFi WiFi CEF рядок payloadAsUTF: "
            f"{payload}"
        )
        return None

    mac = normalise_mac_address(mac_raw)
    name = name_raw if name_raw else "unknown"

    epoch_raw = None
    unifi_utc = fields.get("unifiutctime")
    if unifi_utc:
        epoch_raw = parse_unifi_utc_time(unifi_utc)

    if stats:
        stats.unifi_processed += 1

    return ip, mac, name, epoch_raw


def parse_cef_payload(payload: str) -> Tuple[str, str, str] | None:
    # CEF format: header components separated by '|' with extension at the end.
    msg = extract_cef_msg(payload)
    if not msg:
        return None

    return parse_standard_payload(msg)


def should_skip_cef_client_message(payload: str) -> bool:
    cleaned = payload.strip()
    if "CEF:" not in cleaned:
        return False

    msg = extract_cef_msg(cleaned)
    if not msg:
        return False

    stripped = msg.strip()
    if CEF_CLIENT_MESSAGE_PATTERN.match(stripped):
        return True

    lowered = stripped.lower()
    return "dhcp-client on" in lowered and "got ip address" in lowered


def parse_payload(payload: str, *, stats: DhcpLineStats | None = None) -> Tuple[str, str, str] | None:
    cleaned = payload.strip()
    if is_dnsmasq_dhcpack(cleaned):
        return parse_dnsmasq_dhcpack(cleaned, stats=stats)

    if "CEF:" in cleaned:
        parsed = parse_cef_payload(cleaned)
        if parsed:
            return parsed
        # fall back to standard parsing if CEF parsing fails

    return parse_standard_payload(cleaned)


def build_header_map(header: List[str]) -> Dict[str, int]:
    lowered = {column.lower(): index for index, column in enumerate(header)}
    return lowered


def detect_time_column(header_map: Dict[str, int]) -> str | None:
    for field in TIME_FIELDS:
        key = field.lower()
        if key in header_map:
            return key
    return None


def detect_payload_column(csv_path: Path, header: List[str]) -> str:
    lowered_header = [column.lower() for column in header]
    if "payloadasutf" in lowered_header:
        return header[lowered_header.index("payloadasutf")]

    try:
        with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
            sample = handle.read(4096)
            handle.seek(0)
            dialect = sniff_dialect(sample)
            reader = csv.reader(handle, dialect)
            next(reader, None)

            for row in reader:
                if not row:
                    continue

                for index, value in enumerate(row):
                    if "dhcp,info" in (value or "").lower():
                        if index < len(header):
                            return header[index]
                        return ""
    except OSError as exc:  # pragma: no cover - filesystem error
        raise OSError(f"Помилка читання файлу: {exc}") from exc

    raise ValueError(
        f"Не вдалося визначити payloadAsUTF: жоден стовпчик не містить \"dhcp,info\" у файлі {csv_path}"
    )


def build_dhcp_column_mapping(csv_path: Path, header: List[str]) -> DhcpColumnMapping:
    header_map = build_header_map(header)

    time_column = detect_time_column(header_map)
    if time_column is None:
        raise ValueError(
            f"Відсутні часові поля deviceTime та Log Source Time у файлі {csv_path}"
        )

    has_standard_fields = all(field.lower() in header_map for field in MANDATORY_FIELDS)
    use_log_source_time = "devicetime" not in header_map and time_column == "log source time"

    if use_log_source_time and not has_standard_fields:
        payload_column = detect_payload_column(csv_path, header)
        payload_index = header.index(payload_column)
        source_column = "log source identifier"
        mac_column = "source mac"

        if source_column not in header_map or mac_column not in header_map:
            missing = []
            if source_column not in header_map:
                missing.append("Log Source Identifier")
            if mac_column not in header_map:
                missing.append("Source MAC")
            raise ValueError(f"Відсутні поля: {', '.join(missing)}")

        return DhcpColumnMapping(
            source_index=header_map[source_column],
            mac_index=header_map[mac_column],
            payload_index=payload_index,
            time_index=header_map[time_column],
            time_column_name=time_column,
            use_log_source_time=True,
            payload_column_name=payload_column,
            is_alternative_mapping=True,
        )

    missing = [field for field in MANDATORY_FIELDS if field.lower() not in header_map]
    if missing:
        raise ValueError(f"Відсутні поля: {', '.join(missing)}")

    payload_column = header[[column.lower() for column in header].index("payloadasutf")]

    return DhcpColumnMapping(
        source_index=header_map["logsourceidentifier"],
        mac_index=header_map["sourcmacaddress"],
        payload_index=header_map["payloadasutf"],
        time_index=header_map[time_column],
        time_column_name=time_column,
        use_log_source_time=use_log_source_time,
        payload_column_name=payload_column,
        is_alternative_mapping=False,
    )


def read_rows(csv_path: Path, header: List[str]) -> Iterable[List[str]]:
    try:
        with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
            sample = handle.read(4096)
            handle.seek(0)
            dialect = sniff_dialect(sample)
            reader = csv.reader(handle, dialect)
            next(reader, None)  # skip header
            yield from reader
    except OSError as exc:  # pragma: no cover - filesystem error
        raise OSError(f"Помилка читання файлу: {exc}") from exc


def run_dhcp_aggregation(repo_root: Path, args: argparse.Namespace | None = None) -> int:
    dhcp_dir = repo_root / "data" / "raw" / "dhcp"
    interim_dir = repo_root / "data" / "interim"
    output_path = interim_dir / "dhcp.csv"

    files = list(iter_dhcp_csv_files(dhcp_dir))
    if not files:
        print("❌ DHCP файли відсутні у data/raw/dhcp/")
        return 0

    aggregations: Dict[str, MacAggregation] = {}
    processed_records = 0
    skipped_payload_rows = 0
    skipped_cef_client_rows = 0
    dhcp_line_stats = DhcpLineStats()

    for file_path in files:
        rel_path = file_path.relative_to(repo_root)

        try:
            header = read_csv_header(file_path)
            mapping = build_dhcp_column_mapping(file_path, header)
        except (OSError, ValueError) as exc:
            print(f"❌ Виявлено помилки структури CSV у {rel_path}")
            message = str(exc).replace(str(file_path), str(rel_path))
            print(message)
            print("\nЗупинка обробки.")
            return 1

        if mapping.is_alternative_mapping:
            payload_column_log = mapping.payload_column_name or "(без назви)"
            print(
                f"🔧 Файл {rel_path}: використано Log Source Time, "
                "мапінг полів застосовано, payloadAsUTF визначено як стовпчик "
                f"\"{payload_column_log}\""
            )

        try:
            for row in read_rows(file_path, header):
                if not row:
                    continue

                try:
                    source = row[mapping.source_index].strip()
                    mac = row[mapping.mac_index].strip().upper()
                    payload = row[mapping.payload_index].strip()
                    epoch_raw = row[mapping.time_index].strip()
                except IndexError as exc:
                    raise ValueError("Рядок має менше значень, ніж очікується") from exc

                if not mac or not payload or not epoch_raw:
                    raise ValueError("Рядок містить порожні обовʼязкові поля")

                if should_skip_cef_client_message(payload):
                    skipped_cef_client_rows += 1
                    continue

                dnsmasq_detected = is_dnsmasq_dhcpack(payload)
                unifi_detected = is_unifi_wifi_cef(payload)
                if unifi_detected:
                    parsed_unifi = parse_unifi_wifi_cef(
                        payload, stats=dhcp_line_stats
                    )
                    if not parsed_unifi:
                        skipped_payload_rows += 1
                        continue
                    ip, payload_mac, name, unifi_epoch = parsed_unifi
                    if unifi_epoch:
                        epoch_raw = unifi_epoch
                elif dnsmasq_detected:
                    parsed = parse_dnsmasq_dhcpack(payload, stats=dhcp_line_stats)
                    if not parsed:
                        skipped_payload_rows += 1
                        continue
                    ip, payload_mac, name = parsed
                elif "CEF:" in payload:
                    parsed = parse_payload(payload, stats=dhcp_line_stats)
                    if not parsed:
                        print(f"⚠️ Неможливо розпарсити рядок payloadAsUTF: {payload}")
                        skipped_payload_rows += 1
                        continue
                    ip, payload_mac, name = parsed
                else:
                    body = extract_standard_body(payload, stats=dhcp_line_stats)
                    if should_skip_standard_client_body(body):
                        dhcp_line_stats.skipped_client_rows += 1
                        continue
                    parsed = parse_standard_body(body)
                    if not parsed:
                        print(f"⚠️ Неможливо розпарсити рядок payloadAsUTF: {payload}")
                        skipped_payload_rows += 1
                        continue
                    ip, payload_mac, name = parsed

                if payload_mac != mac:
                    mac = payload_mac

                use_log_source_time = (
                    mapping.use_log_source_time
                    or mapping.time_column_name == "log source time" and not epoch_raw.isdigit()
                )
                if use_log_source_time:
                    epoch_value, seconds = parse_log_source_time(epoch_raw)
                    epoch_raw = str(epoch_value)
                else:
                    epoch_value, seconds = parse_epoch(epoch_raw)

                aggregation = aggregations.setdefault(mac, MacAggregation(mac))
                aggregation.add_entry(
                    source=source,
                    ip=ip,
                    name=name,
                    epoch_raw=epoch_raw,
                    epoch_value=epoch_value,
                    seconds=seconds,
                )
                processed_records += 1
        except ValueError as exc:
            print(f"❌ Помилка обробки CSV у {rel_path}")
            print(str(exc))
            print("\nЗупинка обробки.")
            return 1

    if not aggregations:
        print("❌ Не вдалося знайти жодного запису DHCP")
        return 1

    interim_dir.mkdir(parents=True, exist_ok=True)

    oui_path = repo_root / "data" / "cache" / "oui.csv"
    vendor_map = load_oui_vendor_map(oui_path)

    columns = [
        "source",
        "ip",
        "mac",
        "vendor",
        "name",
        "firstDate",
        "lastDate",
        "firstDateEpoch",
        "lastDateEpoch",
        "count",
        "randomized",
        "dateList",
    ]

    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(columns)
        written_rows = 0

        for mac in sorted(aggregations.keys()):
            agg = aggregations[mac]

            if agg.first_epoch is None or agg.last_epoch is None:
                continue

            first_date = epoch_to_str(agg.first_seconds)
            last_date = epoch_to_str(agg.last_seconds)
            date_list = ", ".join(agg.sorted_epoch_strings())
            randomized_bool = is_randomized_mac(agg.mac)
            randomized = "true" if randomized_bool else "false"
            vendor = resolve_vendor(agg.mac, vendor_map, randomized_bool)

            writer.writerow(
                [
                    agg.last_source,
                    agg.last_ip,
                    agg.mac,
                    vendor,
                    agg.last_name,
                    first_date,
                    last_date,
                    agg.first_epoch,
                    agg.last_epoch,
                    str(agg.count),
                    randomized,
                    date_list,
                ]
            )
            written_rows += 1

    print(f"✅ DHCP логів оброблено: {processed_records}")
    if skipped_payload_rows:
        print(f"⚠️ Пропущено некоректних рядків: {skipped_payload_rows}")
    else:
        print("✅ Некоректні рядки відсутні")
    print(
        "🔧 CEF: пропущено службових рядків dhcp-client: "
        f"{skipped_cef_client_rows}"
    )
    print(
        "🔧 Префіксовані DHCP-рядки: опрацьовано="
        f"{dhcp_line_stats.prefixed_processed}"
    )
    print(
        "🔧 Пропущено client-рядків (префікс/стандарт): "
        f"{dhcp_line_stats.skipped_client_rows}"
    )
    print(
        "✅ DNSMASQ DHCPACK рядків оброблено: "
        f"{dhcp_line_stats.dnsmasq_processed}"
    )
    print(
        "⚠️ DNSMASQ DHCPACK рядків пропущено: "
        f"{dhcp_line_stats.dnsmasq_skipped}"
    )
    print(
        "✅ UniFi WiFi CEF подій оброблено: "
        f"{dhcp_line_stats.unifi_processed}"
    )
    print(
        "⚠️ UniFi WiFi CEF подій пропущено: "
        f"{dhcp_line_stats.unifi_skipped}"
    )
    output_rel = output_path.relative_to(repo_root)
    print(
        "✅ Дані збережено до "
        f"{output_rel} (унікальних MAC-адрес: {written_rows})"
    )
    print(CONSOLE_SEPARATOR)
    return 0


def iter_mac_csv_files(mac_dir: Path) -> Iterable[Path]:
    if not mac_dir.exists():
        return []

    files = sorted(
        path for path in mac_dir.glob("*.csv") if not path.name.endswith(".example.csv")
    )
    return files


def normalise_mac(value: str) -> str:
    return value.replace("-", ":").upper()


HEADER_NORMALISE_PATTERN = re.compile(r"[^0-9a-zа-яіїєґё]+", re.IGNORECASE)
NAME_HEADER_VARIANTS = {
    "имякомпьютера",
    "імякомпютера",
    "computername",
    "hostname",
    "devicehostname",
}


def normalise_header(value: str) -> str:
    cleaned = (value or "").strip().lower()
    cleaned = cleaned.replace("'", "").replace("\u2019", "")
    return HEADER_NORMALISE_PATTERN.sub("", cleaned)


def detect_name_column(fieldnames: Iterable[str]) -> str | None:
    for field in fieldnames:
        normalised = normalise_header(field)
        if normalised in NAME_HEADER_VARIANTS:
            return field

    for field in fieldnames:
        normalised = normalise_header(field)
        if "name" in normalised or "компют" in normalised or "компьют" in normalised:
            return field

    return None


def detect_mac_columns(fieldnames: Iterable[str]) -> List[str]:
    mac_columns = [field for field in fieldnames if "mac" in normalise_header(field)]
    return mac_columns


def guess_delimiter(sample: str) -> str:
    for delimiter in (";", ",", "\t", "|"):
        if delimiter in sample:
            return delimiter
    return ";"


def normalise_device_name(value: str | None) -> str:
    cleaned = (value or "").strip()
    if not cleaned:
        return "unknown"

    cleaned = cleaned.replace("\"", " ").replace("'", " ").replace(",", " ")
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if not cleaned:
        return "unknown"

    return cleaned.upper()


def extract_mac_records_from_row(
    row: Dict[str, str], mac_columns: List[str], name_column: str | None
) -> List[Tuple[str, str]]:
    values_to_scan: List[str] = []

    if mac_columns:
        for column in mac_columns:
            values_to_scan.append((row.get(column) or ""))
    else:
        for key, value in row.items():
            if key is None:
                continue
            values_to_scan.append(value or "")

    found_macs: List[str] = []
    seen: set[str] = set()

    for raw_value in values_to_scan:
        if not isinstance(raw_value, str):
            continue
        for match in MAC_PATTERN.finditer(raw_value):
            mac = normalise_mac(match.group(0))
            if mac not in seen:
                seen.add(mac)
                found_macs.append(mac)

    if not found_macs:
        for key, value in row.items():
            if key is None or not isinstance(value, str):
                continue
            for match in MAC_PATTERN.finditer(value):
                mac = normalise_mac(match.group(0))
                if mac not in seen:
                    seen.add(mac)
                    found_macs.append(mac)

    if not found_macs:
        return []

    raw_name = row.get(name_column, "") if name_column else ""
    name = normalise_device_name(raw_name)
    return [(mac, name) for mac in found_macs]


def iter_rds_csv_files(rds_dir: Path) -> Iterable[Path]:
    if not rds_dir.exists():
        return []

    files = sorted(
        path for path in rds_dir.glob("*.csv") if not path.name.endswith(".example.csv")
    )
    return files


def parse_rds_timestamp(value: str) -> int:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("empty timestamp")

    dt = datetime.strptime(cleaned, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC_TZ)
    epoch = int(dt.timestamp())
    return epoch


def is_ipv4(value: str) -> bool:
    if not value:
        return False

    pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    if not pattern.match(value):
        return False

    try:
        return all(0 <= int(part) <= 255 for part in value.split("."))
    except ValueError:
        return False


def extract_ips(value: str) -> List[str]:
    if not value:
        return []

    return re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", value)


def normalise_rds_name(name: str, alt_name: str, ip: str) -> str:
    cleaned_name = (name or "").strip()
    if not cleaned_name:
        return "unknown"

    if is_ipv4(cleaned_name):
        return "unknown"

    cleaned_ip = (ip or "").strip()
    if cleaned_ip and cleaned_name == cleaned_ip:
        return "unknown"

    alt_ips = extract_ips(alt_name or "")
    if any(cleaned_name == alt_ip for alt_ip in alt_ips):
        return "unknown"

    return cleaned_name


def run_mac_scan(repo_root: Path, args: argparse.Namespace | None = None) -> int:
    mac_dir = repo_root / "data" / "raw" / "av-mac"
    interim_dir = repo_root / "data" / "interim"
    output_path = interim_dir / "mac.csv"

    files = list(iter_mac_csv_files(mac_dir))

    mac_sources: Dict[str, str] = {}
    mac_names: Dict[str, Tuple[int, int, str]] = {}
    total_records = 0
    record_index = 0

    for file_path in files:
        rel_path = file_path.relative_to(repo_root)
        try:
            with file_path.open("r", encoding="utf-8-sig", errors="ignore") as handle:
                content = handle.read()
        except OSError as exc:
            print(f"⚠️ Неможливо прочитати {rel_path}: {exc}")
            continue

        if not content:
            continue

        sample = "\n".join(content.splitlines()[:10])
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
            reader = csv.DictReader(io.StringIO(content), dialect=dialect)
        except csv.Error:
            delimiter = guess_delimiter(sample)
            reader = csv.DictReader(io.StringIO(content), delimiter=delimiter)

        fieldnames = [name or "" for name in reader.fieldnames or []]
        name_column = detect_name_column(fieldnames)
        mac_columns = detect_mac_columns(fieldnames)

        records_in_file: List[Tuple[str, str]] = []

        try:
            for row in reader:
                if row is None:
                    continue
                filtered_row = {key: (value or "") for key, value in row.items() if key is not None}
                entries = extract_mac_records_from_row(filtered_row, mac_columns, name_column)
                if not entries:
                    continue
                records_in_file.extend(entries)
        except csv.Error:
            records_in_file = []

        if not records_in_file:
            for match in MAC_PATTERN.finditer(content):
                normalised_mac = normalise_mac(match.group(0))
                records_in_file.append((normalised_mac, "unknown"))

        for mac, name in records_in_file:
            record_index += 1
            total_records += 1
            mac_sources.setdefault(mac, file_path.name)

            existing = mac_names.get(mac)
            if name == "unknown":
                if existing is None:
                    mac_names[mac] = (record_index, 0, "unknown")
                continue

            candidate_length = len(name)
            if (
                existing is None
                or existing[2] == "unknown"
                or candidate_length > existing[1]
                or (candidate_length == existing[1] and record_index >= existing[0])
            ):
                mac_names[mac] = (record_index, candidate_length, name)

    if not mac_sources:
        print("⚠️ MAC-адрес не знайдено у data/raw/av-mac/*.csv")
        return 0

    interim_dir.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["mac", "source", "name"])
        for mac in sorted(mac_sources.keys()):
            name_info = mac_names.get(mac)
            resolved_name = name_info[2] if name_info else "unknown"
            writer.writerow([mac, mac_sources[mac], resolved_name])

    print(f"✅ Виявлено AV-записів: {total_records}")
    print(f"✅ Унікальних MAC-адрес: {len(mac_sources)}")
    print("✅ Додано колонку name з іменами комп’ютерів")
    print("✅ Збережено файл: data/interim/mac.csv")
    print(CONSOLE_SEPARATOR)
    return 0


def run_get_oui(repo_root: Path, args: argparse.Namespace | None = None) -> int:
    cache_dir = repo_root / "data" / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    output_path = cache_dir / "oui.csv"
    url = "https://standards-oui.ieee.org/oui/oui.csv"

    try:
        with urllib.request.urlopen(url) as response:
            data = response.read()
    except (urllib.error.URLError, OSError):
        print("⚠️ Не вдалося завантажити OUI-довідник")
        return 1

    try:
        with output_path.open("wb") as handle:
            handle.write(data)
    except OSError:
        print("⚠️ Не вдалося завантажити OUI-довідник")
        return 1

    print("✅ OUI-довідник завантажено: data/cache/oui.csv")
    print(CONSOLE_SEPARATOR)
    return 0


def generate_rds_result_files(repo_root: Path) -> int:
    interim_dir = repo_root / "data" / "interim"
    result_dir = repo_root / "data" / "result"

    rds_path = interim_dir / "rds.csv"
    mac_path = interim_dir / "mac.csv"

    if not rds_path.exists():
        print("❌ Файл data/interim/rds.csv не знайдено")
        return 1

    if not mac_path.exists():
        print("❌ Файл data/interim/mac.csv не знайдено")
        return 1

    try:
        with mac_path.open("r", encoding="utf-8-sig", newline="") as mac_handle:
            mac_reader = csv.DictReader(mac_handle)
            mac_headers = mac_reader.fieldnames or []
            if "mac" not in mac_headers:
                print("❌ Файл data/interim/mac.csv не містить колонки 'mac'")
                return 1
            mac_set: Set[str] = {
                (row.get("mac") or "").strip().upper()
                for row in mac_reader
                if (row.get("mac") or "").strip()
            }
    except OSError as exc:
        print(f"❌ Неможливо прочитати data/interim/mac.csv: {exc}")
        return 1

    if not mac_set:
        print("⚠️ У data/interim/mac.csv відсутні MAC-адреси для порівняння")

    ignore_rules_path = repo_root / "configs" / "device_ignore.yml"
    ignore_config = load_device_ignore_rules(ignore_rules_path)
    network_rules_path = repo_root / "configs" / "device_network.yml"
    network_config = load_device_rules(network_rules_path)

    result_dir.mkdir(parents=True, exist_ok=True)

    for path in result_dir.glob("rds-*.csv"):
        try:
            path.unlink()
        except OSError:
            continue

    random_path = result_dir / "rds-random.csv"
    ignore_path = result_dir / "rds-ignore.csv"
    network_path = result_dir / "rds-network.csv"
    true_path = result_dir / "rds-true.csv"
    false_path = result_dir / "rds-false.csv"

    ignored_count = 0
    random_count = 0
    match_count = 0
    miss_count = 0
    total_rows = 0

    all_rows: List[Dict[str, str]] = []

    try:
        with rds_path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            headers = reader.fieldnames
            if not headers:
                print("❌ Файл data/interim/rds.csv не містить заголовок")
                return 1

            with (
                random_path.open("w", encoding="utf-8", newline="") as random_handle,
                ignore_path.open("w", encoding="utf-8", newline="") as ignore_handle,
                true_path.open("w", encoding="utf-8", newline="") as true_handle,
                false_path.open("w", encoding="utf-8", newline="") as false_handle,
            ):
                writer_random = csv.DictWriter(random_handle, fieldnames=headers)
                writer_ignore = csv.DictWriter(ignore_handle, fieldnames=headers)
                writer_true = csv.DictWriter(true_handle, fieldnames=headers)
                writer_false = csv.DictWriter(false_handle, fieldnames=headers)

                writer_random.writeheader()
                writer_ignore.writeheader()
                writer_true.writeheader()
                writer_false.writeheader()

                for row in reader:
                    if row is None:
                        continue

                    row_copy = {key: value for key, value in row.items()}
                    all_rows.append(row_copy)

                    total_rows += 1

                    randomized_value = (row_copy.get("randomized") or "").strip().lower()
                    if randomized_value == "true":
                        writer_random.writerow(row_copy)
                        random_count += 1
                        continue

                    name_value = (row_copy.get("name") or "").strip()
                    if matches_device_rules(name_value, ignore_config.name_rules) or device_matches_vendor_rules(
                        row_copy,
                        ignore_config.vendor_rules,
                        config_label=ignore_config.label or "device_ignore.yml",
                    ):
                        writer_ignore.writerow(row_copy)
                        ignored_count += 1
                        continue

                    if matches_device_rules(name_value, network_config.name_rules) or device_matches_vendor_rules(
                        row_copy,
                        network_config.vendor_rules,
                        config_label=network_config.label or "device_network.yml",
                    ):
                        # Network matches are collected in a dedicated pass later
                        continue

                    mac_value = (row_copy.get("mac") or "").strip().upper()
                    if mac_value and mac_value in mac_set:
                        writer_true.writerow(row_copy)
                        match_count += 1
                    else:
                        writer_false.writerow(row_copy)
                        miss_count += 1
    except OSError as exc:
        print(f"❌ Неможливо прочитати data/interim/rds.csv: {exc}")
        return 1

    vendor_stats = VendorRuleStats(
        config_label=network_config.label or network_rules_path.name
    )
    matched_network_rows: List[Dict[str, str]] = []

    for row in all_rows:
        name_value = (row.get("name") or "").strip()
        matched_by_name = matches_device_rules(name_value, network_config.name_rules)
        matched_by_vendor = device_matches_vendor_rules(
            row,
            network_config.vendor_rules,
            config_label=network_config.label or "device_network.yml",
            stats=vendor_stats,
        )

        if matched_by_name or matched_by_vendor:
            matched_network_rows.append(row)

    try:
        with network_path.open("w", encoding="utf-8", newline="") as network_handle:
            writer_network = csv.DictWriter(network_handle, fieldnames=headers)
            writer_network.writeheader()
            writer_network.writerows(matched_network_rows)
    except OSError as exc:
        print(f"❌ Неможливо оновити data/result/rds-network.csv: {exc}")
        return 1

    network_count = len(matched_network_rows)

    print(vendor_stats.summary_line())
    print("✅ Обробку правил vendor завершено успішно.")

    print(f"✅ Виявлено RDS-записів у data/interim/rds.csv: {total_rows}")
    print(f"✅ Виявлено MAC-адрес із random: {random_count}")
    print(f"✅ Виявлено пристроїв, що відповідають правилам ignore: {ignored_count}")
    print(f"✅ Виявлено мережевих пристроїв: {network_count}")
    print(f"✅ Виявлено RDS із AV-збігом: {match_count}")
    print(f"⚠️ Виявлено RDS без AV-збігу: {miss_count}")
    print("✅ Усі результати збережено до data/result/")
    print(CONSOLE_SEPARATOR)
    return 0


def run_rds_aggregation(repo_root: Path, args: argparse.Namespace | None = None) -> int:
    rds_dir = repo_root / "data" / "raw" / "rds"
    interim_dir = repo_root / "data" / "interim"
    output_path = interim_dir / "rds.csv"

    files = list(iter_rds_csv_files(rds_dir))
    if not files:
        print("❌ RDS файли відсутні у data/raw/rds/")
        return 0

    vendor_map = load_oui_vendor_map(repo_root / "data" / "cache" / "oui.csv")

    aggregations: Dict[str, RdsAggregation] = {}
    total_records = 0

    required_columns = {
        "RemoteHost",
        "Адрес IPv4",
        "Имя хоста",
        "Альтернативные имена хостов",
        "MAC-адрес",
        "Время повторения",
    }

    for csv_path in files:
        rel_path = csv_path.relative_to(repo_root)

        try:
            with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
                reader = csv.DictReader(handle, delimiter=";")
                headers = reader.fieldnames or []
                missing = [column for column in required_columns if column not in headers]
                if missing:
                    print(
                        f"⚠️ Пропуск файлу {rel_path}: відсутні колонки {', '.join(sorted(missing))}"
                    )
                    continue

                for row in reader:
                    if row is None:
                        continue

                    mac_raw = (row.get("MAC-адрес") or "").strip()
                    if not mac_raw:
                        continue

                    time_raw = (row.get("Время повторения") or "").strip()
                    if not time_raw:
                        continue

                    try:
                        epoch = parse_rds_timestamp(time_raw)
                    except ValueError:
                        print(
                            f"⚠️ Пропуск запису у {rel_path}: некоректне значення часу '{time_raw}'"
                        )
                        continue

                    mac = normalise_mac(mac_raw)
                    source = (row.get("RemoteHost") or "").strip()
                    ip = (row.get("Адрес IPv4") or "").strip()
                    alt_name = (row.get("Альтернативные имена хостов") or "").strip()
                    name_raw = row.get("Имя хоста") or ""
                    name = normalise_rds_name(name_raw, alt_name, ip)

                    aggregation = aggregations.setdefault(mac, RdsAggregation(mac=mac))
                    aggregation.add_entry(source=source, ip=ip, name=name, epoch=epoch)

                    total_records += 1
        except OSError as exc:
            print(f"⚠️ Неможливо прочитати {rel_path}: {exc}")

    interim_dir.mkdir(parents=True, exist_ok=True)

    columns = [
        "source",
        "ip",
        "mac",
        "vendor",
        "name",
        "firstDate",
        "lastDate",
        "firstDateEpoch",
        "lastDateEpoch",
        "count",
        "randomized",
        "dateList",
    ]

    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(columns)

        for mac in sorted(aggregations.keys()):
            aggregation = aggregations[mac]
            if aggregation.first_epoch is None or aggregation.last_epoch is None:
                continue

            first_date = epoch_to_str(float(aggregation.first_epoch))
            last_date = epoch_to_str(float(aggregation.last_epoch))
            randomized_bool = is_randomized_mac(mac)
            vendor = resolve_vendor(mac, vendor_map, randomized_bool)
            date_list = ", ".join(str(epoch) for epoch in aggregation.sorted_epochs())

            writer.writerow(
                [
                    aggregation.last_source,
                    aggregation.last_ip,
                    mac,
                    vendor,
                    aggregation.last_name,
                    first_date,
                    last_date,
                    str(aggregation.first_epoch),
                    str(aggregation.last_epoch),
                    str(aggregation.count),
                    "true" if randomized_bool else "false",
                    date_list,
                ]
            )

    print(f"✅ Виявлено RDS-записів (усі файли): {total_records}")
    print(f"✅ Унікальних MAC-адрес у RDS: {len(aggregations)}")
    print("✅ Збережено агрегований файл: data/interim/rds.csv")

    return generate_rds_result_files(repo_root)


def write_network_results(
    *,
    dhcp_path: Path,
    network_path: Path,
    network_config: DeviceFilterConfig,
    include_randomized: bool,
    vendor_stats: VendorRuleStats | None = None,
) -> tuple[int, bool]:
    try:
        with dhcp_path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            headers = reader.fieldnames
            if not headers:
                print("❌ Файл data/interim/dhcp.csv не містить заголовок")
                return 0, False

            try:
                with network_path.open("w", encoding="utf-8", newline="") as network_handle:
                    writer_network = csv.DictWriter(network_handle, fieldnames=headers)
                    writer_network.writeheader()

                    network_count = 0
                    config_label = network_config.label or "device_network.yml"

                    for row in reader:
                        if row is None:
                            continue

                        randomized_value = (row.get("randomized") or "").strip().lower()
                        if not include_randomized and randomized_value == "true":
                            continue

                        name_value = (row.get("name") or "").strip()

                        if matches_device_rules(name_value, network_config.name_rules) or device_matches_vendor_rules(
                            row,
                            network_config.vendor_rules,
                            config_label=config_label,
                            stats=vendor_stats,
                        ):
                            writer_network.writerow(row)
                            network_count += 1

            except OSError as exc:
                print(f"❌ Неможливо записати data/result/dhcp-network.csv: {exc}")
                return 0, False

    except OSError as exc:
        print(f"❌ Неможливо прочитати data/interim/dhcp.csv: {exc}")
        return 0, False

    return network_count, True


def run_compare_dhcp_and_mac(repo_root: Path, args: argparse.Namespace | None = None) -> int:
    interim_dir = repo_root / "data" / "interim"
    result_dir = repo_root / "data" / "result"

    cleanup_result_directory(result_dir)

    mac_path = interim_dir / "mac.csv"
    dhcp_path = interim_dir / "dhcp.csv"
    ignore_rules_path = repo_root / "configs" / "device_ignore.yml"

    ignore_config = load_device_ignore_rules(ignore_rules_path)
    network_rules_path = repo_root / "configs" / "device_network.yml"
    network_config = load_device_rules(network_rules_path)
    include_randomized_network = bool(getattr(args, "include_randomized_network", False))
    ignore_stats = (
        VendorRuleStats(ignore_config.label or "device_ignore.yml")
        if ignore_config.vendor_rules
        else None
    )
    network_stats = (
        VendorRuleStats(network_config.label or "device_network.yml")
        if network_config.vendor_rules
        else None
    )

    if not dhcp_path.exists():
        print("❌ Файл data/interim/dhcp.csv не знайдено")
        return 1

    if not mac_path.exists():
        print("❌ Файл data/interim/mac.csv не знайдено")
        return 1

    try:
        with mac_path.open("r", encoding="utf-8-sig", newline="") as handle:
            mac_reader = csv.DictReader(handle)
            mac_fieldnames = mac_reader.fieldnames or []
            if "mac" not in mac_fieldnames:
                print("❌ Файл data/interim/mac.csv не містить колонки 'mac'")
                return 1
            mac_set = {
                (row.get("mac") or "").strip().upper()
                for row in mac_reader
                if (row.get("mac") or "").strip()
            }
    except OSError as exc:
        print(f"❌ Неможливо прочитати data/interim/mac.csv: {exc}")
        return 1

    if not mac_set:
        print("⚠️ У data/interim/mac.csv відсутні MAC-адреси для порівняння")

    result_dir.mkdir(parents=True, exist_ok=True)

    true_path = result_dir / "dhcp-true.csv"
    false_path = result_dir / "dhcp-false.csv"
    ignore_path = result_dir / "dhcp-ignore.csv"
    random_path = result_dir / "dhcp-random.csv"

    ignored_count = 0
    random_count = 0

    try:
        with dhcp_path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            headers = reader.fieldnames
            if not headers:
                print("❌ Файл data/interim/dhcp.csv не містить заголовок")
                return 1

            with true_path.open("w", encoding="utf-8", newline="") as true_handle, \
                false_path.open("w", encoding="utf-8", newline="") as false_handle, \
                ignore_path.open("w", encoding="utf-8", newline="") as ignore_handle, \
                random_path.open("w", encoding="utf-8", newline="") as random_handle:

                writer_true = csv.DictWriter(true_handle, fieldnames=headers)
                writer_false = csv.DictWriter(false_handle, fieldnames=headers)
                writer_ignore = csv.DictWriter(ignore_handle, fieldnames=headers)
                writer_random = csv.DictWriter(random_handle, fieldnames=headers)
                writer_true.writeheader()
                writer_false.writeheader()
                writer_ignore.writeheader()
                writer_random.writeheader()

                match_count = 0
                miss_count = 0

                for row in reader:
                    if row is None:
                        continue

                    randomized_value = (row.get("randomized") or "").strip().lower()
                    if randomized_value == "true":
                        writer_random.writerow(row)
                        random_count += 1
                        continue
                    if randomized_value != "false":
                        continue

                    name_value = (row.get("name") or "").strip()
                    if matches_device_rules(name_value, ignore_config.name_rules):
                        ignored_count += 1
                        writer_ignore.writerow(row)
                        continue

                    if device_matches_vendor_rules(
                        row,
                        ignore_config.vendor_rules,
                        config_label=ignore_config.label or "device_ignore.yml",
                        stats=ignore_stats,
                    ):
                        ignored_count += 1
                        writer_ignore.writerow(row)
                        continue

                    mac_value = (row.get("mac") or "").strip().upper()
                    if mac_value and mac_value in mac_set:
                        writer_true.writerow(row)
                        match_count += 1
                    else:
                        writer_false.writerow(row)
                        miss_count += 1
    except OSError as exc:
        print(f"❌ Неможливо прочитати data/interim/dhcp.csv: {exc}")
        return 1

    print(f"🔹 Випадкових MAC-адрес виявлено: {random_count}")
    print("📁 Збережено до data/result/dhcp-random.csv")
    print(f"🟡 Ігноровано за правилами: {ignored_count}")
    print(f"✅ Виявлено пристроїв з АВПЗ: {match_count}")
    print(f"⚠️ Виявлено пристроїв без АВПЗ: {miss_count}")
    print(
        "📁 Результати збережено до data/result/dhcp-true.csv, data/result/dhcp-false.csv та data/result/dhcp-ignore.csv"
    )
    print(CONSOLE_SEPARATOR)

    move_name_duplicates(result_dir)

    network_path = result_dir / "dhcp-network.csv"
    network_count, network_success = write_network_results(
        dhcp_path=dhcp_path,
        network_path=network_path,
        network_config=network_config,
        include_randomized=include_randomized_network,
        vendor_stats=network_stats,
    )

    if not network_success:
        return 1

    print(f"🔷 Віднесено до мережевих пристроїв: {network_count}")
    print("📁 Збережено до data/result/dhcp-network.csv")
    print(CONSOLE_SEPARATOR)
    if network_stats is not None:
        print(network_stats.summary_line())
    if ignore_stats is not None:
        print(ignore_stats.summary_line())
    if network_stats is not None or ignore_stats is not None:
        print("✅ Обробку правил vendor завершено успішно.")
    print("✅ Дані успішно оброблено та збережено у data/result/")

    return 0


def sanitise_source_name(value: str) -> str:
    if not value:
        return "unknown"

    safe = re.sub(r"[^0-9A-Za-z._-]", "_", value)
    return safe or "unknown"


def normalise_source_value(value: str) -> str:
    value = value.strip()
    return value or "unknown"


def collect_source_periods(dhcp_dir: Path) -> Dict[str, Tuple[float, float]]:
    periods: Dict[str, Tuple[float, float]] = {}

    for csv_path in iter_dhcp_csv_files(dhcp_dir):
        try:
            with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
                reader = csv.DictReader(handle)
                for row in reader:
                    if row is None:
                        continue

                    source_raw = (row.get("logSourceIdentifier") or "").strip()
                    device_time = (row.get("deviceTime") or "").strip()

                    if not source_raw or not device_time:
                        continue

                    try:
                        _, seconds = parse_epoch(device_time)
                    except ValueError:
                        continue
                    source = normalise_source_value(source_raw)

                    if source in periods:
                        current_min, current_max = periods[source]
                        periods[source] = (
                            min(current_min, seconds),
                            max(current_max, seconds),
                        )
                    else:
                        periods[source] = (seconds, seconds)
        except OSError as exc:
            print(f"⚠️ Неможливо прочитати {csv_path.as_posix()}: {exc}")

    return periods


def load_dhcp_false_data(false_path: Path) -> Tuple[Dict[str, List[Dict[str, str]]], List[str]]:
    sources: DefaultDict[str, List[Dict[str, str]]] = defaultdict(list)
    missing_fields: List[str] = []

    try:
        with false_path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            headers = reader.fieldnames or []
            if "source" not in headers:
                missing_fields.append("source")
                return {}, missing_fields

            for row in reader:
                if row is None:
                    continue

                source_value = normalise_source_value(row.get("source") or "")

                device: Dict[str, str] = {}
                for field in ["name", "mac", "ip", "lastDate", "count", "lastDateEpoch"]:
                    value = (row.get(field) or "").strip()
                    device[field] = value if value else "unknown"

                sources[source_value].append(device)
    except OSError as exc:
        print(f"❌ Неможливо прочитати data/result/dhcp-false.csv: {exc}")
        return {}, []

    return sources, missing_fields


def render_report_content(
    *,
    source: str,
    devices: List[Dict[str, str]],
    periods: Dict[str, Tuple[float, float]],
) -> str:
    lines: List[str] = []
    period = periods.get(source)

    if period is None:
        lines.append(
            f'Період спостереження: дані відсутні у сирих DHCP-логах для джерела "{source}".'
        )
    else:
        min_date = epoch_to_str(period[0])
        max_date = epoch_to_str(period[1])
        lines.append(f"Період спостереження з {min_date} по {max_date}")

    lines.append("")

    if not devices:
        lines.append(
            f'На локації з джерелом журналів подій "{source}" пристроїв не виявлено.'
        )
        return "\n".join(lines).rstrip() + "\n"

    device_count = len(devices)
    lines.append(
        "На локації з джерелом журналів подій "
        f'"{source}" виявлено {device_count} пристроїв, імовірно таких, що функціонують без АВПЗ.'
    )
    lines.append("")

    def sort_key(device: Dict[str, str]) -> Tuple[int, int]:
        epoch_raw = device.get("lastDateEpoch") or "unknown"
        try:
            epoch_value = int(epoch_raw)
        except ValueError:
            return (0, 0)
        return (1, epoch_value)

    sorted_devices = sorted(devices, key=sort_key, reverse=True)

    for index, device in enumerate(sorted_devices):
        name = device.get("name") or "unknown"
        mac = device.get("mac") or "unknown"
        ip = device.get("ip") or "unknown"
        last_date = device.get("lastDate") or "unknown"
        count = device.get("count") or "unknown"

        lines.append(f'Пристрій "{name}" — MAC {mac}, IP {ip}.')
        lines.append(
            "Останнє отримання мережевих налаштувань від DHCP серверу: "
            f"{last_date}."
        )
        lines.append(
            "Загальна кількість отримань за період спостереження: "
            f"{count}."
        )
        if index != len(sorted_devices) - 1:
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def run_generate_reports(repo_root: Path, args: argparse.Namespace | None = None) -> int:
    result_dir = repo_root / "data" / "result"
    report_dir = repo_root / "data" / "report"
    dhcp_dir = repo_root / "data" / "raw" / "dhcp"

    false_path = result_dir / "dhcp-false.csv"

    if not false_path.exists():
        print("❌ Файл data/result/dhcp-false.csv не знайдено")
        return 1

    grouped_devices, missing_fields = load_dhcp_false_data(false_path)

    if missing_fields:
        print("❌ Файл data/result/dhcp-false.csv не містить колонку 'source'")
        return 1

    if not grouped_devices:
        print("⚠️ Файл data/result/dhcp-false.csv порожній або не містить записів")
        return 0

    periods = collect_source_periods(dhcp_dir)

    report_dir.mkdir(parents=True, exist_ok=True)

    report_count = 0

    for source in sorted(grouped_devices):
        devices = grouped_devices[source]
        report_name = f"report-{sanitise_source_name(source)}.txt"
        report_path = report_dir / report_name

        content = render_report_content(source=source, devices=devices, periods=periods)

        try:
            with report_path.open("w", encoding="utf-8") as handle:
                handle.write(content)
        except OSError as exc:
            print(f"❌ Неможливо записати {report_path.as_posix()}: {exc}")
            return 1

        report_count += 1
        print(f"📄 Створено звіт: {report_path.relative_to(repo_root)}")

    print(f"✅ Загалом сформовано звітів: {report_count}")
    print(CONSOLE_SEPARATOR)
    return 0


def run_all(repo_root: Path, args: argparse.Namespace | None = None) -> int:
    dhcp_result = run_dhcp_aggregation(repo_root)
    if dhcp_result != 0:
        return dhcp_result

    mac_result = run_mac_scan(repo_root)
    if mac_result != 0:
        return mac_result

    return run_compare_dhcp_and_mac(repo_root, args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Утиліта для обробки даних Poshukach",
    )
    subparsers = parser.add_subparsers(dest="command")

    dhcp_parser = subparsers.add_parser(
        "dhcp-aggregate",
        help="Агрегувати DHCP журнали у data/interim/dhcp.csv",
    )
    dhcp_parser.set_defaults(command_func=run_dhcp_aggregation)

    mac_parser = subparsers.add_parser(
        "mac-scan",
        help="Зібрати унікальні MAC-адреси з data/raw/av-mac",
    )
    mac_parser.set_defaults(command_func=run_mac_scan)

    rds_parser = subparsers.add_parser(
        "rds",
        help="Агрегувати RDS журнали у data/interim/rds.csv",
    )
    rds_parser.set_defaults(command_func=run_rds_aggregation)

    oui_parser = subparsers.add_parser(
        "get_oui",
        help="Завантажити довідник OUI до data/cache/oui.csv",
    )
    oui_parser.set_defaults(command_func=run_get_oui)

    compare_parser = subparsers.add_parser(
        "compare-dhcp-mac",
        help="Порівняти MAC-адреси з data/interim/dhcp.csv та data/interim/mac.csv",
    )
    compare_parser.add_argument(
        "--include-randomized-network",
        action="store_true",
        help="Включити randomized-записи до результату dhcp-network.csv",
    )
    compare_parser.set_defaults(command_func=run_compare_dhcp_and_mac)

    all_parser = subparsers.add_parser(
        "all",
        help="Послідовно виконати обробку DHCP та MAC-адрес",
    )
    all_parser.add_argument(
        "--include-randomized-network",
        action="store_true",
        help="Включити randomized-записи до результату dhcp-network.csv",
    )
    all_parser.set_defaults(command_func=run_all)

    report_parser = subparsers.add_parser(
        "report",
        help="Згенерувати текстові звіти для джерел із data/result/dhcp-false.csv",
    )
    report_parser.set_defaults(command_func=run_generate_reports)

    return parser


def main(argv: List[str] | None = None) -> int:
    set_max_csv_field_size()
    repo_root = Path(__file__).resolve().parent.parent
    parser = build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "command", None) is None:
        oui_path = repo_root / "data" / "cache" / "oui.csv"
        if not oui_path.exists():
            print("⚠️ Файл data/cache/oui.csv відсутній.")
            print("  ➜ Запустіть команду: python3 scripts/psh.py get_oui")
            return 1

    command_func = getattr(args, "command_func", run_all)
    return command_func(repo_root, args)


if __name__ == "__main__":
    sys.exit(main())
