import csv
import pathlib
import sys

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import psh  # type: ignore  # noqa: E402


def test_run_dhcp_aggregation_supports_log_source_time(tmp_path: pathlib.Path):
    repo_root = tmp_path
    dhcp_dir = repo_root / "data" / "raw" / "dhcp"
    dhcp_dir.mkdir(parents=True, exist_ok=True)

    dhcp_file = dhcp_dir / "sample.csv"
    dhcp_file.write_text(
        (
            "logSourceIdentifier,sourcMACAddress,payloadAsUTF,Log Source Time\n"
            '"10.0.0.10","00:11:22:33:44:55",'
            '"dhcp,info defconf assigned 192.168.1.60 for 00:11:22:33:44:55 Laptop",'
            '"Dec 31, 2025, 1:32:58 PM"\n'
        ),
        encoding="utf-8",
    )

    result = psh.run_dhcp_aggregation(repo_root)

    assert result == 0
    output_path = repo_root / "data" / "interim" / "dhcp.csv"
    assert output_path.exists()

    with output_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)

    assert len(rows) == 1
    row = rows[0]
    assert row["firstDateEpoch"] == "1767180778000"
    assert row["lastDateEpoch"] == "1767180778000"
    assert row["dateList"] == "1767180778000"
    assert row["firstDate"] == "2025.12.31 13:32"
    assert row["lastDate"] == "2025.12.31 13:32"


def test_run_dhcp_aggregation_requires_time_column(
    tmp_path: pathlib.Path, capsys
) -> None:
    repo_root = tmp_path
    dhcp_dir = repo_root / "data" / "raw" / "dhcp"
    dhcp_dir.mkdir(parents=True, exist_ok=True)

    dhcp_file = dhcp_dir / "missing_time.csv"
    dhcp_file.write_text(
        (
            "logSourceIdentifier,sourcMACAddress,payloadAsUTF\n"
            '"10.0.0.10","AA:BB:CC:DD:EE:FF",'
            '"dhcp,info defconf assigned 192.168.1.60 for AA:BB:CC:DD:EE:FF"\n'
        ),
        encoding="utf-8",
    )

    result = psh.run_dhcp_aggregation(repo_root)

    assert result == 1
    captured = capsys.readouterr()
    assert (
        "Відсутні часові поля deviceTime та Log Source Time у файлі data/raw/dhcp/missing_time.csv"
        in captured.out
    )


def test_run_dhcp_aggregation_prefers_device_time_when_available(
    tmp_path: pathlib.Path,
) -> None:
    repo_root = tmp_path
    dhcp_dir = repo_root / "data" / "raw" / "dhcp"
    dhcp_dir.mkdir(parents=True, exist_ok=True)

    dhcp_file = dhcp_dir / "with_device_time.csv"
    dhcp_file.write_text(
        (
            "logSourceIdentifier,sourcMACAddress,payloadAsUTF,deviceTime,Log Source Time\n"
            '"10.0.0.10","00:11:22:33:44:55",'
            '"dhcp,info defconf assigned 192.168.1.60 for 00:11:22:33:44:55 Laptop",'
            '"1755006684895","Dec 31, 2025, 1:32:58 PM"\n'
        ),
        encoding="utf-8",
    )

    result = psh.run_dhcp_aggregation(repo_root)

    assert result == 0
    output_path = repo_root / "data" / "interim" / "dhcp.csv"
    with output_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)

    assert len(rows) == 1
    row = rows[0]
    assert row["firstDateEpoch"] == "1755006684895"
    assert row["lastDateEpoch"] == "1755006684895"
    assert row["dateList"] == "1755006684895"
    assert row["firstDate"] == "2025.08.12 16:51"
    assert row["lastDate"] == "2025.08.12 16:51"


def test_run_dhcp_aggregation_alt_columns_with_payload_detection(
    tmp_path: pathlib.Path, capsys
) -> None:
    repo_root = tmp_path
    dhcp_dir = repo_root / "data" / "raw" / "dhcp"
    dhcp_dir.mkdir(parents=True, exist_ok=True)

    dhcp_file = dhcp_dir / "alt_columns.csv"
    dhcp_file.write_text(
        (
            "Log Source Identifier,Source MAC,custom1,,Log Source Time\n"
            '"10.0.0.20","AA:BB:CC:DD:EE:FF",'
            '"DHCP,INFO defconf assigned 192.168.10.5 for AA:BB:CC:DD:EE:FF Laptop",,'
            '"Dec 31, 2025, 1:32:58 PM"\n'
        ),
        encoding="utf-8",
    )

    result = psh.run_dhcp_aggregation(repo_root)

    captured = capsys.readouterr()
    assert result == 0
    assert 'payloadAsUTF визначено як стовпчик "custom1"' in captured.out

    output_path = repo_root / "data" / "interim" / "dhcp.csv"
    with output_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)

    assert len(rows) == 1
    row = rows[0]
    assert row["mac"] == "AA:BB:CC:DD:EE:FF"
    assert row["firstDateEpoch"] == "1767180778000"
    assert row["lastDateEpoch"] == "1767180778000"
    assert row["dateList"] == "1767180778000"
    assert row["source"] == "10.0.0.20"


def test_run_dhcp_aggregation_detects_payload_with_duplicate_empty_headers(
    tmp_path: pathlib.Path, capsys
) -> None:
    repo_root = tmp_path
    dhcp_dir = repo_root / "data" / "raw" / "dhcp"
    dhcp_dir.mkdir(parents=True, exist_ok=True)

    dhcp_file = dhcp_dir / "duplicate_headers.csv"
    dhcp_file.write_text(
        (
            "Event Name,Log Source Identifier,Source MAC,Log Source Time,,,\n"
            '"DHCP: IP Assigned","10.10.130.176","EE:D1:41:47:B2:21","Dec 31, 2025, 2:32:59 PM",'
            '"dhcp,info defconf assigned 192.168.88.115 for EE:D1:41:47:B2:21 iPhone",'
            '"64 68 63 70 2c 69 6e 66 6f 20 64 65 66 63 6f 6e 66 20 61 73 73 69 67 6e 65 64 20 31 39 32 2e 31 36 38 2e 38 38 2e 31 31 35 20 66 6f 72 20 45 45 3a 44 31 3a 34 31 3a 34 37 3a 42 32 3a 32 31 20 69 50 68 6f 6e 65",'
            '"ZGhjcCxpbmZvIGRlZmNvbmYgYXNzaWduZWQgMTkyLjE2OC44OC4xMTUgZm9yIEVFOkQxOjQxOjQ3OkIyOjIxIGlQaG9uZQ=="\n'
        ),
        encoding="utf-8",
    )

    expected_epoch, _ = psh.parse_log_source_time("Dec 31, 2025, 2:32:59 PM")

    result = psh.run_dhcp_aggregation(repo_root)

    captured = capsys.readouterr()
    assert result == 0
    assert 'payloadAsUTF визначено як стовпчик "(без назви)"' in captured.out

    output_path = repo_root / "data" / "interim" / "dhcp.csv"
    with output_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)

    assert len(rows) == 1
    row = rows[0]
    assert row["mac"] == "EE:D1:41:47:B2:21"
    assert row["ip"] == "192.168.88.115"
    assert row["name"] == "iPhone"
    assert row["firstDateEpoch"] == str(expected_epoch)
    assert row["lastDateEpoch"] == str(expected_epoch)
    assert row["dateList"] == str(expected_epoch)
    assert row["source"] == "10.10.130.176"


def test_run_dhcp_aggregation_alt_columns_missing_payload_detection(
    tmp_path: pathlib.Path, capsys
) -> None:
    repo_root = tmp_path
    dhcp_dir = repo_root / "data" / "raw" / "dhcp"
    dhcp_dir.mkdir(parents=True, exist_ok=True)

    dhcp_file = dhcp_dir / "alt_columns_invalid.csv"
    dhcp_file.write_text(
        (
            "Log Source Identifier,Source MAC,custom1,Log Source Time\n"
            '"10.0.0.20","AA:BB:CC:DD:EE:FF","unrelated text","Dec 31, 2025, 1:32:58 PM"\n'
        ),
        encoding="utf-8",
    )

    result = psh.run_dhcp_aggregation(repo_root)

    captured = capsys.readouterr()
    assert result == 1
    assert (
        "Не вдалося визначити payloadAsUTF: жоден стовпчик не містить \"dhcp,info\" у файлі"
        in captured.out
    )
