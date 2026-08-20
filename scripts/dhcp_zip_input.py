"""ZIP input support for DHCP CSV processing.

This module keeps the existing CSV parsing pipeline unchanged. It only expands
ZIP archives from data/raw/dhcp into temporary CSV files and returns those
paths together with the direct CSV inputs discovered by the original iterator.
"""

from __future__ import annotations

import atexit
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable, List


_DIRECT_ITERATOR = Callable[[Path], Iterable[Path]]
_TEMP_DIRECTORIES: List[tempfile.TemporaryDirectory] = []
_SAFE_NAME_PATTERN = re.compile(r"[^0-9A-Za-z._-]+")


def _cleanup_temp_directories() -> None:
    while _TEMP_DIRECTORIES:
        temp_dir = _TEMP_DIRECTORIES.pop()
        try:
            temp_dir.cleanup()
        except OSError:
            pass


atexit.register(_cleanup_temp_directories)


def cleanup_dhcp_zip_inputs() -> None:
    """Remove all temporary directories created for ZIP DHCP inputs."""

    _cleanup_temp_directories()


def _safe_name(value: str) -> str:
    cleaned = _SAFE_NAME_PATTERN.sub("_", value).strip("._")
    return cleaned or "unknown"


def _safe_member_parts(member_name: str) -> List[str] | None:
    normalized = member_name.replace("\\", "/")
    path = PurePosixPath(normalized)

    if path.is_absolute() or any(part == ".." for part in path.parts):
        return None

    parts = [part for part in path.parts if part not in {"", "."}]
    return parts or None


def _unique_destination(temp_root: Path, base_name: str) -> Path:
    candidate = temp_root / base_name
    if not candidate.exists():
        return candidate

    stem = candidate.stem
    suffix = candidate.suffix
    counter = 2
    while True:
        candidate = temp_root / f"{stem}__{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def _iter_zip_archives(dhcp_dir: Path) -> List[Path]:
    if not dhcp_dir.exists():
        return []

    return sorted(
        (
            path
            for path in dhcp_dir.iterdir()
            if path.is_file() and path.suffix.casefold() == ".zip"
        ),
        key=lambda path: path.name.casefold(),
    )


def _remove_partial_file(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def _validate_extracted_csv(
    destination: Path,
    *,
    archive_path: Path,
    member: zipfile.ZipInfo,
) -> bool:
    """Validate a CSV extracted from ZIP before exposing it to the parser."""

    try:
        actual_size = destination.stat().st_size
    except OSError as exc:
        print(
            f'⚠️ ZIP {archive_path.name}: CSV {member.filename} пропущено - '
            f"не вдалося перевірити temporary file: {exc}"
        )
        _remove_partial_file(destination)
        return False

    if actual_size == 0:
        print(
            f'⚠️ ZIP {archive_path.name}: CSV {member.filename} пропущено - '
            "файл порожній після extraction"
        )
        _remove_partial_file(destination)
        return False

    if member.file_size != actual_size:
        print(
            f'⚠️ ZIP {archive_path.name}: CSV {member.filename} пропущено - '
            f"неповний extraction (очікувалось {member.file_size} байт, "
            f"отримано {actual_size})"
        )
        _remove_partial_file(destination)
        return False

    try:
        with destination.open("rb") as handle:
            has_nonempty_line = any(line.strip() for line in handle)
    except OSError as exc:
        print(
            f'⚠️ ZIP {archive_path.name}: CSV {member.filename} пропущено - '
            f"не вдалося прочитати temporary file: {exc}"
        )
        _remove_partial_file(destination)
        return False

    if not has_nonempty_line:
        print(
            f'⚠️ ZIP {archive_path.name}: CSV {member.filename} пропущено - '
            "файл не містить непорожніх рядків після extraction"
        )
        _remove_partial_file(destination)
        return False

    return True


def _extract_archive_csv_files(archive_path: Path, temp_root: Path) -> List[Path]:
    extracted: List[Path] = []
    archive_prefix = _safe_name(archive_path.stem)

    try:
        archive = zipfile.ZipFile(archive_path)
    except (OSError, zipfile.BadZipFile) as exc:
        print(f"⚠️ Неможливо прочитати ZIP-архів {archive_path.name}: {exc}")
        return extracted

    with archive:
        for member in archive.infolist():
            if member.is_dir():
                continue

            parts = _safe_member_parts(member.filename)
            if parts is None:
                print(
                    f"⚠️ Пропущено небезпечний шлях у ZIP-архіві {archive_path.name}: "
                    f"{member.filename}"
                )
                continue

            original_name = parts[-1]
            if Path(original_name).suffix.casefold() != ".csv":
                continue
            if original_name.casefold().endswith(".example.csv"):
                continue

            member_token = "__".join(_safe_name(part) for part in parts)
            destination = _unique_destination(
                temp_root,
                f"{archive_prefix}__{member_token}",
            )
            partial = destination.with_name(f".{destination.name}.part")
            _remove_partial_file(partial)

            try:
                with archive.open(member, "r") as source, partial.open("wb") as target:
                    shutil.copyfileobj(source, target)
                    target.flush()
                    os.fsync(target.fileno())
                partial.replace(destination)
            except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                _remove_partial_file(partial)
                _remove_partial_file(destination)
                print(
                    f"⚠️ Неможливо прочитати CSV {member.filename} "
                    f"з ZIP-архіву {archive_path.name}: {exc}"
                )
                continue

            if not _validate_extracted_csv(
                destination,
                archive_path=archive_path,
                member=member,
            ):
                continue

            print(f"🔧 ZIP {archive_path.name}: extracted CSV {member.filename}")
            extracted.append(destination)

    return extracted


def iter_dhcp_csv_files_with_archives(
    dhcp_dir: Path,
    direct_iterator: _DIRECT_ITERATOR,
) -> List[Path]:
    """Return direct DHCP CSVs plus CSV files extracted from ZIP archives.

    Direct CSV discovery is delegated to the original iterator so its existing
    behaviour remains unchanged. ZIP entries are extracted into a temporary
    directory outside data/raw/dhcp and are cleaned after the command finishes
    (or at interpreter shutdown as a fallback).
    """

    direct_files = list(direct_iterator(dhcp_dir))
    archives = _iter_zip_archives(dhcp_dir)
    if not archives:
        return direct_files

    temp_parent = dhcp_dir.parent
    temp_parent.mkdir(parents=True, exist_ok=True)
    temp_dir = tempfile.TemporaryDirectory(prefix=".dhcp-zip-", dir=temp_parent)
    _TEMP_DIRECTORIES.append(temp_dir)
    temp_root = Path(temp_dir.name)

    extracted: List[Path] = []
    for archive_path in archives:
        extracted.extend(_extract_archive_csv_files(archive_path, temp_root))

    return sorted(
        [*direct_files, *extracted],
        key=lambda path: path.as_posix().casefold(),
    )
