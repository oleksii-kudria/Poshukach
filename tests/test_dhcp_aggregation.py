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
