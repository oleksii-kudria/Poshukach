#!/usr/bin/env python3
"""CLI utilities for working with Poshukach datasets.

The implementation remains in ``psh_core``. This compatibility entrypoint adds
ZIP-backed DHCP CSV discovery while preserving the existing public API used by
CLI commands and tests.
"""

from __future__ import annotations

import sys

import psh_core as _core
from dhcp_zip_input import cleanup_dhcp_zip_inputs, iter_dhcp_csv_files_with_archives
from psh_core import *  # noqa: F401,F403


_ORIGINAL_ITER_DHCP_CSV_FILES = _core.iter_dhcp_csv_files
_ORIGINAL_RUN_DHCP_AGGREGATION = _core.run_dhcp_aggregation
_ORIGINAL_RUN_GENERATE_REPORTS = _core.run_generate_reports


def iter_dhcp_csv_files(dhcp_dir):
    return iter_dhcp_csv_files_with_archives(
        dhcp_dir,
        _ORIGINAL_ITER_DHCP_CSV_FILES,
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
