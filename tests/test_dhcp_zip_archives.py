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
