import csv
import pathlib
import sys
import zipfile

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import psh  # type: ignore  # noqa: E402


def _dhcp_csv(source: str, mac: str, ip: str, name: str, epoch: str) -> str:
    return (
        "logSourceIdentifier,sourcMACAddress,payloadAsUTF,deviceTime\n"
        f'"{source}","{mac}",'
        f'"dhcp,info defconf assigned {ip} for {mac} {name}",'
        f'"{epoch}"\n'
    )


def _production_csv(source: str, mac: str, ip: str, name: str, timestamp: str) -> str:
    return (
        "Log Source Time,Log Source Identifier,Source MAC,Payload\n"
        f'"{timestamp}","{source}","{mac}",'
        f'"dhcp,info DHCP_EXAMPLE assigned {ip} for {mac} {name}"\n'
    )


def _read_output(repo_root: pathlib.Path):
    output_path = repo_root / "data" / "interim" / "dhcp.csv"
    with output_path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def test_zip_archive_processes_only_csv_including_nested_files(tmp_path: pathlib.Path):
    dhcp_dir = tmp_path / "data" / "raw" / "dhcp"
    dhcp_dir.mkdir(parents=True)

    with zipfile.ZipFile(dhcp_dir / "logs.zip", "w") as archive:
        archive.writestr(
            "dhcp.csv",
            _dhcp_csv("10.0.0.1", "00:11:22:33:44:55", "192.168.1.10", "One", "1755006684895"),
        )
        archive.writestr(
            "nested/dhcp.csv",
            _dhcp_csv("10.0.0.2", "00:11:22:33:44:66", "192.168.1.11", "Two", "1755006685895"),
        )
        archive.writestr("readme.txt", "ignored")
        archive.writestr("image.png", b"not-an-image")

    assert psh.run_dhcp_aggregation(tmp_path) == 0

    rows = _read_output(tmp_path)
    assert {row["mac"] for row in rows} == {
        "00:11:22:33:44:55",
        "00:11:22:33:44:66",
    }
    assert not list((tmp_path / "data" / "raw").glob(".dhcp-zip-*"))


def test_same_csv_name_in_different_archives_does_not_overwrite(tmp_path: pathlib.Path):
    dhcp_dir = tmp_path / "data" / "raw" / "dhcp"
    dhcp_dir.mkdir(parents=True)

    with zipfile.ZipFile(dhcp_dir / "first.zip", "w") as archive:
        archive.writestr(
            "dhcp.csv",
            _dhcp_csv("10.0.0.1", "00:11:22:33:44:55", "192.168.1.10", "One", "1755006684895"),
        )
    with zipfile.ZipFile(dhcp_dir / "second.zip", "w") as archive:
        archive.writestr(
            "dhcp.csv",
            _dhcp_csv("10.0.0.2", "00:11:22:33:44:66", "192.168.1.11", "Two", "1755006685895"),
        )

    assert psh.run_dhcp_aggregation(tmp_path) == 0
    assert len(_read_output(tmp_path)) == 2


def test_direct_csv_and_zip_csv_are_processed_together(tmp_path: pathlib.Path):
    dhcp_dir = tmp_path / "data" / "raw" / "dhcp"
    dhcp_dir.mkdir(parents=True)

    (dhcp_dir / "direct.csv").write_text(
        _dhcp_csv("10.0.0.1", "00:11:22:33:44:55", "192.168.1.10", "Direct", "1755006684895"),
        encoding="utf-8",
    )
    with zipfile.ZipFile(dhcp_dir / "archive.zip", "w") as archive:
        archive.writestr(
            "dhcp.csv",
            _dhcp_csv("10.0.0.2", "00:11:22:33:44:66", "192.168.1.11", "Archived", "1755006685895"),
        )

    assert psh.run_dhcp_aggregation(tmp_path) == 0
    rows = _read_output(tmp_path)
    assert {row["name"] for row in rows} == {"Direct", "Archived"}


def test_corrupted_zip_does_not_stop_other_inputs(tmp_path: pathlib.Path, capsys):
    dhcp_dir = tmp_path / "data" / "raw" / "dhcp"
    dhcp_dir.mkdir(parents=True)

    (dhcp_dir / "broken.zip").write_bytes(b"this-is-not-a-zip")
    (dhcp_dir / "direct.csv").write_text(
        _dhcp_csv("10.0.0.1", "00:11:22:33:44:55", "192.168.1.10", "Direct", "1755006684895"),
        encoding="utf-8",
    )

    assert psh.run_dhcp_aggregation(tmp_path) == 0
    captured = capsys.readouterr()
    assert "Неможливо прочитати ZIP-архів broken.zip" in captured.out
    assert len(_read_output(tmp_path)) == 1


def test_zip_slip_entry_is_ignored(tmp_path: pathlib.Path, capsys):
    dhcp_dir = tmp_path / "data" / "raw" / "dhcp"
    dhcp_dir.mkdir(parents=True)

    with zipfile.ZipFile(dhcp_dir / "safe.zip", "w") as archive:
        archive.writestr(
            "../../malicious.csv",
            _dhcp_csv("10.0.0.9", "00:11:22:33:44:99", "192.168.1.99", "Bad", "1755006689895"),
        )
        archive.writestr(
            "safe.csv",
            _dhcp_csv("10.0.0.1", "00:11:22:33:44:55", "192.168.1.10", "Safe", "1755006684895"),
        )

    assert psh.run_dhcp_aggregation(tmp_path) == 0
    captured = capsys.readouterr()
    assert "Пропущено небезпечний шлях" in captured.out
    rows = _read_output(tmp_path)
    assert len(rows) == 1
    assert rows[0]["name"] == "Safe"
    assert not (tmp_path / "malicious.csv").exists()


def test_zip_and_csv_extensions_are_case_insensitive_inside_archives(tmp_path: pathlib.Path):
    dhcp_dir = tmp_path / "data" / "raw" / "dhcp"
    dhcp_dir.mkdir(parents=True)

    with zipfile.ZipFile(dhcp_dir / "ARCHIVE.ZIP", "w") as archive:
        archive.writestr(
            "DHCP.CSV",
            _dhcp_csv("10.0.0.1", "00:11:22:33:44:55", "192.168.1.10", "Upper", "1755006684895"),
        )
        archive.writestr(
            "sample.example.csv",
            _dhcp_csv("10.0.0.2", "00:11:22:33:44:66", "192.168.1.11", "Ignored", "1755006685895"),
        )

    assert psh.run_dhcp_aggregation(tmp_path) == 0
    rows = _read_output(tmp_path)
    assert len(rows) == 1
    assert rows[0]["name"] == "Upper"


def test_zip_regression_supports_log_source_time_source_mac_payload_header(
    tmp_path: pathlib.Path,
):
    dhcp_dir = tmp_path / "data" / "raw" / "dhcp"
    dhcp_dir.mkdir(parents=True)

    csv_content = _production_csv(
        "10.0.0.10",
        "00:11:22:33:44:55",
        "192.168.11.234",
        "TL-WR840N",
        "Aug 11, 2026, 8:13:32 PM",
    )

    with zipfile.ZipFile(dhcp_dir / "2026-08-20-data_export.csv_1.zip", "w") as archive:
        archive.writestr("2026-08-20-data_export.csv", csv_content)

    assert psh.run_dhcp_aggregation(tmp_path) == 0
    rows = _read_output(tmp_path)
    assert len(rows) == 1
    assert rows[0]["source"] == "10.0.0.10"
    assert rows[0]["mac"] == "00:11:22:33:44:55"
    assert rows[0]["ip"] == "192.168.11.234"
    assert rows[0]["name"] == "TL-WR840N"


def test_empty_csv_in_zip_is_skipped_without_stopping_valid_csv(
    tmp_path: pathlib.Path,
    capsys,
):
    dhcp_dir = tmp_path / "data" / "raw" / "dhcp"
    dhcp_dir.mkdir(parents=True)

    with zipfile.ZipFile(dhcp_dir / "mixed.zip", "w") as archive:
        archive.writestr("empty.csv", b"")
        archive.writestr(
            "valid.csv",
            _dhcp_csv("10.0.0.1", "00:11:22:33:44:55", "192.168.1.10", "Valid", "1755006684895"),
        )

    assert psh.run_dhcp_aggregation(tmp_path) == 0
    captured = capsys.readouterr()
    assert "CSV empty.csv пропущено" in captured.out
    assert "файл порожній після extraction" in captured.out
    rows = _read_output(tmp_path)
    assert len(rows) == 1
    assert rows[0]["name"] == "Valid"


def test_empty_csv_in_one_archive_does_not_block_other_archives(
    tmp_path: pathlib.Path,
    capsys,
):
    dhcp_dir = tmp_path / "data" / "raw" / "dhcp"
    dhcp_dir.mkdir(parents=True)

    with zipfile.ZipFile(dhcp_dir / "first.zip", "w") as archive:
        archive.writestr(
            "valid1.csv",
            _dhcp_csv("10.0.0.1", "00:11:22:33:44:55", "192.168.1.10", "One", "1755006684895"),
        )
    with zipfile.ZipFile(dhcp_dir / "second.zip", "w") as archive:
        archive.writestr("empty.csv", b"")
    with zipfile.ZipFile(dhcp_dir / "third.zip", "w") as archive:
        archive.writestr(
            "valid2.csv",
            _dhcp_csv("10.0.0.2", "00:11:22:33:44:66", "192.168.1.11", "Two", "1755006685895"),
        )

    assert psh.run_dhcp_aggregation(tmp_path) == 0
    captured = capsys.readouterr()
    assert "ZIP second.zip: CSV empty.csv пропущено" in captured.out
    rows = _read_output(tmp_path)
    assert {row["name"] for row in rows} == {"One", "Two"}


def test_duplicate_empty_then_valid_member_uses_valid_content(
    tmp_path: pathlib.Path,
    capsys,
):
    dhcp_dir = tmp_path / "data" / "raw" / "dhcp"
    dhcp_dir.mkdir(parents=True)

    with zipfile.ZipFile(dhcp_dir / "duplicates.zip", "w") as archive:
        archive.writestr("data.csv", b"")
        archive.writestr(
            "data.csv",
            _dhcp_csv("10.0.0.3", "00:11:22:33:44:77", "192.168.1.12", "Recovered", "1755006686895"),
        )

    assert psh.run_dhcp_aggregation(tmp_path) == 0
    captured = capsys.readouterr()
    assert "CSV data.csv пропущено" in captured.out
    rows = _read_output(tmp_path)
    assert len(rows) == 1
    assert rows[0]["name"] == "Recovered"
