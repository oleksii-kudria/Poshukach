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
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import DefaultDict, Dict, Iterable, List, Pattern, Tuple

import yaml

MAC_PATTERN = re.compile(r"""(?i)\b([0-9a-f]{2}([-:]))(?:[0-9a-f]{2}\2){4}[0-9a-f]{2}\b""")

CONSOLE_SEPARATOR = "--------------------------------------------"

DeviceRule = Tuple[str, List[object]]


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
    patterns: List[str]
    require: VendorRequireConfig | None = None
    except_: VendorExceptConfig | None = None


@dataclass
class DeviceFilterConfig:
    name_rules: List[DeviceRule] = field(default_factory=list)
    vendor_rules: List[VendorRule] = field(default_factory=list)
    label: str = ""


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
                        patterns=[pattern.lower() for pattern in patterns],
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


def match_vendor_patterns(vendor: str, patterns: List[str]) -> bool:
    if not patterns:
        return False

    value = vendor or ""
    lowered = value.lower()

    return any(pattern in lowered for pattern in patterns)


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
    "deviceTime",
]

PAYLOAD_PATTERN = re.compile(
    r"assigned\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+for\s+"
    r"(?P<mac>[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})(?P<name>.*)$"
)

CLIENT_MESSAGE_PATTERN = re.compile(r"^dhcp,info\s+dhcp-client\s+on", re.IGNORECASE)



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


def epoch_to_str(seconds: float) -> str:
    dt = datetime.utcfromtimestamp(seconds)
    return dt.strftime("%Y.%m.%d %H:%M")


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


def is_client_message(payload: str) -> bool:
    return bool(CLIENT_MESSAGE_PATTERN.search(payload.strip()))


def parse_payload(payload: str) -> Tuple[str, str, str]:
    match = PAYLOAD_PATTERN.search(payload)
    if not match:
        raise ValueError("Неможливо розпарсити payloadAsUTF")

    ip = match.group("ip")
    mac = match.group("mac").upper()
    name = match.group("name").strip()
    if not name:
        name = "unknown"
    return ip, mac, name


def normalise_header(header: List[str]) -> Dict[str, int]:
    lowered = {column.lower(): index for index, column in enumerate(header)}
    return lowered


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

    for file_path in files:
        rel_path = file_path.relative_to(repo_root)

        try:
            header = read_csv_header(file_path)
        except (OSError, ValueError) as exc:
            print(f"❌ Виявлено помилки структури CSV у {rel_path}")
            print(str(exc))
            print("\nЗупинка обробки.")
            return 1

        header_map = normalise_header(header)
        missing = [field for field in MANDATORY_FIELDS if field.lower() not in header_map]
        if missing:
            print(f"❌ Виявлено помилки структури CSV у {rel_path}")
            print(f"Відсутні поля: {', '.join(missing)}")
            print("\nЗупинка обробки.")
            return 1

        try:
            for row in read_rows(file_path, header):
                if not row:
                    continue

                try:
                    source = row[header_map["logsourceidentifier"]].strip()
                    mac = row[header_map["sourcmacaddress"]].strip().upper()
                    payload = row[header_map["payloadasutf"]].strip()
                    epoch_raw = row[header_map["devicetime"]].strip()
                except IndexError as exc:
                    raise ValueError("Рядок має менше значень, ніж очікується") from exc

                if not mac or not payload or not epoch_raw:
                    raise ValueError("Рядок містить порожні обовʼязкові поля")

                if is_client_message(payload):
                    continue

                try:
                    ip, payload_mac, name = parse_payload(payload)
                except ValueError as exc:
                    raise ValueError(f"Помилка парсингу payloadAsUTF: {payload}") from exc

                if payload_mac != mac:
                    mac = payload_mac

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

    print(
        "✅ Виявлено та записано унікальних MAC-адрес до data/interim/dhcp.csv: "
        f"{written_rows}"
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


def run_mac_scan(repo_root: Path, args: argparse.Namespace | None = None) -> int:
    mac_dir = repo_root / "data" / "raw" / "av-mac"
    interim_dir = repo_root / "data" / "interim"
    output_path = interim_dir / "mac.csv"

    files = list(iter_mac_csv_files(mac_dir))

    mac_sources: Dict[str, str] = {}

    for file_path in files:
        rel_path = file_path.relative_to(repo_root)
        try:
            with file_path.open("r", encoding="utf-8-sig", errors="ignore") as handle:
                content = handle.read()
        except OSError as exc:
            print(f"⚠️ Неможливо прочитати {rel_path}: {exc}")
            continue

        for match in MAC_PATTERN.finditer(content):
            normalised = normalise_mac(match.group(0))
            mac_sources.setdefault(normalised, file_path.name)

    if not mac_sources:
        print("⚠️ MAC-адрес не знайдено у data/raw/av-mac/*.csv")
        return 0

    interim_dir.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["mac", "source"])
        for mac in sorted(mac_sources.keys()):
            writer.writerow([mac, mac_sources[mac]])

    print(f"✅ Унікальних MAC-адрес зафіксованих в AV: {len(mac_sources)}")
    print("✅ Результат збережено у data/interim/mac.csv")
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
