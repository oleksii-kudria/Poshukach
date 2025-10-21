#!/usr/bin/env python3
"""CLI utilities for working with Poshukach datasets.

The script provides two main commands:

``dhcp-aggregate``
    Aggregate DHCP log files into ``data/interim/dhcp.csv``. The command
    reads every CSV file in ``data/raw/dhcp`` (excluding ``*.example.csv``),
    validates their headers and then aggregates the records by MAC
    address. The resulting dataset is written to
    ``data/interim/dhcp.csv`` with the following columns::

        source,ip,mac,name,firstDate,lastDate,firstDateEpoch,lastDateEpoch,
        count,randomized,dateList

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
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

MAC_PATTERN = re.compile(r"""(?i)\b([0-9a-f]{2}([-:]))(?:[0-9a-f]{2}\2){4}[0-9a-f]{2}\b""")

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


def run_dhcp_aggregation(repo_root: Path) -> int:
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

    columns = [
        "source",
        "ip",
        "mac",
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
            randomized = "true" if is_randomized_mac(agg.mac) else "false"

            writer.writerow(
                [
                    agg.last_source,
                    agg.last_ip,
                    agg.mac,
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

    print(f"✅ Записано рядків до data/interim/dhcp.csv: {written_rows}")
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


def run_mac_scan(repo_root: Path) -> int:
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

    print(f"✅ Унікальних MAC-адрес: {len(mac_sources)}")
    print("✅ Результат збережено у data/interim/mac.csv")
    return 0


def run_compare_dhcp_and_mac(repo_root: Path) -> int:
    interim_dir = repo_root / "data" / "interim"
    result_dir = repo_root / "data" / "result"

    mac_path = interim_dir / "mac.csv"
    dhcp_path = interim_dir / "dhcp.csv"

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

    try:
        with dhcp_path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            headers = reader.fieldnames
            if not headers:
                print("❌ Файл data/interim/dhcp.csv не містить заголовок")
                return 1

            with true_path.open("w", encoding="utf-8", newline="") as true_handle, \
                false_path.open("w", encoding="utf-8", newline="") as false_handle:

                writer_true = csv.DictWriter(true_handle, fieldnames=headers)
                writer_false = csv.DictWriter(false_handle, fieldnames=headers)
                writer_true.writeheader()
                writer_false.writeheader()

                match_count = 0
                miss_count = 0

                for row in reader:
                    if row is None:
                        continue

                    randomized_value = (row.get("randomized") or "").strip().lower()
                    if randomized_value != "false":
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

    print(f"✅ DHCP збігів знайдено: {match_count}")
    print(f"⚠️ DHCP без збігів: {miss_count}")
    print(
        "📁 Результати збережено до data/result/dhcp-true.csv та data/result/dhcp-false.csv"
    )

    return 0


def run_all(repo_root: Path) -> int:
    dhcp_result = run_dhcp_aggregation(repo_root)
    if dhcp_result != 0:
        return dhcp_result

    mac_result = run_mac_scan(repo_root)
    if mac_result != 0:
        return mac_result

    return run_compare_dhcp_and_mac(repo_root)


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

    compare_parser = subparsers.add_parser(
        "compare-dhcp-mac",
        help="Порівняти MAC-адреси з data/interim/dhcp.csv та data/interim/mac.csv",
    )
    compare_parser.set_defaults(command_func=run_compare_dhcp_and_mac)

    all_parser = subparsers.add_parser(
        "all",
        help="Послідовно виконати обробку DHCP та MAC-адрес",
    )
    all_parser.set_defaults(command_func=run_all)

    return parser


def main(argv: List[str] | None = None) -> int:
    repo_root = Path(__file__).resolve().parent.parent
    parser = build_parser()
    args = parser.parse_args(argv)

    command_func = getattr(args, "command_func", run_all)
    return command_func(repo_root)


if __name__ == "__main__":
    sys.exit(main())
