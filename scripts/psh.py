#!/usr/bin/env python3
"""Utility script for working with DHCP CSV files.

This script searches the ``data/raw/dhcp`` directory for CSV files,
ignoring any files that end with ``.example.csv``. For each file found,
the CSV header is validated to ensure that all mandatory fields are
present. Validation is strict with regard to letter case, but leading
and trailing spaces around the column names are ignored.

If a file fails validation (for example, because it lacks a header, is
empty, or is missing mandatory columns) the script reports the issue
and stops further processing. When all files are valid, a summary
message confirming the successful validation is printed.
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path
from typing import Iterable, List

MANDATORY_FIELDS: List[str] = [
    "logSourceIdentifier",
    "sourcMACAddress",
    "payloadAsUTF",
    "deviceTime",
]


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


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    dhcp_dir = repo_root / "data" / "raw" / "dhcp"

    files = list(iter_dhcp_csv_files(dhcp_dir))
    if not files:
        print("❌ DHCP файли відсутні у data/raw/dhcp/")
        return 0

    print(f"✅ Перевірено {len(files)} файли у data/raw/dhcp/")

    for file_path in files:
        rel_path = file_path.relative_to(repo_root)

        try:
            header = read_csv_header(file_path)
        except OSError as exc:
            print(f"❌ Виявлено помилки структури CSV у {rel_path}")
            print(str(exc))
            print("\nЗупинка обробки.")
            return 1
        except ValueError as exc:
            print(f"❌ Виявлено помилки структури CSV у {rel_path}")
            print(str(exc))
            print("\nЗупинка обробки.")
            return 1

        missing = [field for field in MANDATORY_FIELDS if field not in header]
        if missing:
            print(f"❌ Виявлено помилки структури CSV у {rel_path}")
            print(f"Відсутні поля: {', '.join(missing)}")
            print("\nЗупинка обробки.")
            return 1

        print(f"✅ {file_path.name} — заголовки валідні")

    print(
        "\nУсі файли містять обовʼязкові поля: "
        + ", ".join(MANDATORY_FIELDS)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
