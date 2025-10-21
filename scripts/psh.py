#!/usr/bin/env python3
"""Utility script for working with DHCP CSV files.

This script searches the ``data/raw/dhcp`` directory for CSV files,
ignoring any files that end with ``.example.csv``. For each file found,
its absolute path relative to the repository root and the number of
rows is printed. If no valid CSV files are present, an informative
message is shown instead.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterable


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


def count_rows(csv_path: Path) -> int:
    """Return the number of lines in *csv_path*.

    The count includes header rows. Files are read using UTF-8 encoding,
    which matches the repository's convention for text files.
    """

    with csv_path.open("r", encoding="utf-8") as handle:
        return sum(1 for _ in handle)


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    dhcp_dir = repo_root / "data" / "raw" / "dhcp"

    files = list(iter_dhcp_csv_files(dhcp_dir))
    if not files:
        print("❌ DHCP файли відсутні у data/raw/dhcp/")
        return 0

    for file_path in files:
        rows = count_rows(file_path)
        rel_path = file_path.relative_to(repo_root)
        print(f"✅ Знайдено файл: {rel_path} ({rows} рядки)")

    print(f"\nВсього файлів: {len(files)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
