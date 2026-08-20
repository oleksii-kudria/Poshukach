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
    """Return normal direct CSV files plus CSVs from CSV-named directories.

    Normal direct-file discovery stays delegated to the original iterator.
    Directory paths that the original ``glob("*.csv")`` also returns are
    filtered out so they are never passed to the CSV parser. If such a path is
    a directory whose name ends in ``.csv``, real CSV files below it are found
    recursively and added to the input list.
    """

    if not dhcp_dir.exists():
        return []

    files = []
    seen = set()

    for path in _ORIGINAL_ITER_DHCP_CSV_FILES(dhcp_dir):
        if not _is_real_csv_file(path):
            continue
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        files.append(path)

    csv_named_directories = sorted(
        (
            path
            for path in dhcp_dir.iterdir()
            if path.is_dir() and path.suffix.casefold() == ".csv"
        ),
        key=lambda item: item.name.casefold(),
    )

    for directory in csv_named_directories:
        nested_files = sorted(
            (
                nested
                for nested in directory.rglob("*")
                if _is_real_csv_file(nested)
            ),
            key=lambda item: item.as_posix().casefold(),
        )

        if not nested_files:
            print(
                f"⚠️ DHCP директорія {directory.name}: "
                "CSV файли всередині відсутні"
            )
            continue

        print(
            f"🔧 DHCP директорія {directory.name}: "
            f"знайдено CSV файлів: {len(nested_files)}"
        )
        for nested in nested_files:
            resolved = nested.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            files.append(nested)

    return sorted(files, key=lambda path: path.as_posix().casefold())


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
