#!/usr/bin/env python3
"""CLI utilities for working with Poshukach datasets.

The implementation remains in ``psh_core``. This compatibility entrypoint adds
ZIP-backed DHCP CSV discovery while preserving the existing public API used by
CLI commands and tests.
"""

from __future__ import annotations

import sys
from pathlib import Path

import psh_core as _core
from dhcp_zip_input import cleanup_dhcp_zip_inputs, iter_dhcp_csv_files_with_archives
from psh_core import *  # noqa: F401,F403


_ORIGINAL_ITER_DHCP_CSV_FILES = _core.iter_dhcp_csv_files
_ORIGINAL_RUN_DHCP_AGGREGATION = _core.run_dhcp_aggregation
_ORIGINAL_RUN_GENERATE_REPORTS = _core.run_generate_reports


def _is_real_csv_file(path: Path) -> bool:
    return (
        path.is_file()
        and path.suffix.casefold() == ".csv"
        and not path.name.casefold().endswith(".example.csv")
    )


def _iter_direct_dhcp_csv_files(dhcp_dir: Path):
    """Return real DHCP CSV files and inspect CSV-named directories.

    A path such as ``data/raw/dhcp/export.csv`` may be either a regular file or
    a directory created by an export/unpack workflow. Regular files keep the
    existing behaviour. Directories whose names end with ``.csv`` are never
    passed to the CSV parser; instead, real CSV files below them are discovered
    recursively.
    """

    if not dhcp_dir.exists():
        return []

    files = []
    seen = set()

    for path in sorted(dhcp_dir.iterdir(), key=lambda item: item.name.casefold()):
        if _is_real_csv_file(path):
            resolved = path.resolve()
            if resolved not in seen:
                seen.add(resolved)
                files.append(path)
            continue

        if not path.is_dir() or path.suffix.casefold() != ".csv":
            continue

        nested_files = sorted(
            (
                nested
                for nested in path.rglob("*")
                if _is_real_csv_file(nested)
            ),
            key=lambda item: item.as_posix().casefold(),
        )

        if not nested_files:
            print(f"⚠️ DHCP директорія {path.name}: CSV файли всередині відсутні")
            continue

        print(
            f"🔧 DHCP директорія {path.name}: "
            f"знайдено CSV файлів: {len(nested_files)}"
        )
        for nested in nested_files:
            resolved = nested.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            files.append(nested)

    return files


def iter_dhcp_csv_files(dhcp_dir):
    return iter_dhcp_csv_files_with_archives(
        dhcp_dir,
        _iter_direct_dhcp_csv_files,
    )


def run_dhcp_aggregation(repo_root, args=None):
    cleanup_dhcp_zip_inputs()
    try:
        return _ORIGINAL_RUN_DHCP_AGGREGATION(repo_root, args)
    finally:
        cleanup_dhcp_zip_inputs()


def run_generate_reports(repo_root, args=None):
    cleanup_dhcp_zip_inputs()
    try:
        return _ORIGINAL_RUN_GENERATE_REPORTS(repo_root, args)
    finally:
        cleanup_dhcp_zip_inputs()


# Existing functions in psh_core resolve globals from the psh_core module, so
# patch the three integration points there as well.
_core.iter_dhcp_csv_files = iter_dhcp_csv_files
_core.run_dhcp_aggregation = run_dhcp_aggregation
_core.run_generate_reports = run_generate_reports


if __name__ == "__main__":
    sys.exit(_core.main())
