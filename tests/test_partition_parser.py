import os
import struct
import tempfile
import pytest

from firm_lens.extractor.esp32_extractor import ESP32Extractor
from firm_lens.analyzers.esp32_partition_analyzer import ESP32PartitionAnalyzer


def _build_synthetic_unified_flash() -> bytes:
    """
    Constructs a 4 MB valid ESP32 flash layout:
    - 0x1000: Bootloader header (magic 0xE9, 1 segment, entry 0x40080000)
    - 0x8000: Partition table:
        1. 'nvs' partition (type=0x01, subtype=0x00, offset=0x9000, size=0x6000, flags=0x00 -> unencrypted)
        2. 'factory' partition (type=0x00, subtype=0x00, offset=0x10000, size=0x100000, flags=0x00)
    """
    # 4 MB standard flash buffer
    data = bytearray(b"\xFF" * (4 * 1024 * 1024))

    # 1. Bootloader Header at 0x1000 (<BBBB I)
    data[0x1000:0x1008] = struct.pack("<BBBB I", 0xE9, 1, 0, 0, 0x40080000)
    # Segment 0 definition at 0x1018 (<II -> load_addr, length) + 16 bytes payload
    data[0x1018:0x1020] = struct.pack("<II", 0x40080000, 16)
    data[0x1020:0x1030] = b"\x00" * 16

    # 2. Partition Table Entries at 0x8000 (<HBBII16sI)
    # nvs entry (type 0x01=data, subtype 0x00=ota/nvs, size 0x6000)
    nvs_entry = struct.pack(
        "<HBBII16sI",
        0x50AA, 0x01, 0x00, 0x9000, 0x6000,
        b"nvs\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        0x00  # unencrypted flag
    )
    # factory entry (type 0x00=app, subtype 0x00=factory, size 0x100000 = 1MB)
    factory_entry = struct.pack(
        "<HBBII16sI",
        0x50AA, 0x00, 0x00, 0x10000, 0x100000,
        b"factory\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        0x00
    )

    data[0x8000:0x8020] = nvs_entry
    data[0x8020:0x8040] = factory_entry
    return bytes(data)


def test_esp32_extractor_partition_discovery():
    """Verify ESP32Extractor detects unified flash and parses partition entries."""
    raw_data = _build_synthetic_unified_flash()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
        tmp.write(raw_data)
        tmp_path = tmp.name

    try:
        extractor = ESP32Extractor()
        firmware_map = extractor.extract(tmp_path)

        assert firmware_map is not None
        assert firmware_map["chip"] == "ESP32"
        assert firmware_map["is_unified_flash"] is True
        assert len(firmware_map["partitions"]) == 2

        partition_names = [p["name"] for p in firmware_map["partitions"]]
        assert "nvs" in partition_names
        assert "factory" in partition_names

        nvs_part = next(p for p in firmware_map["partitions"] if p["name"] == "nvs")
        assert nvs_part["offset"] == "0x9000"
        assert nvs_part["size"] == 0x6000
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_esp32_partition_analyzer_findings():
    """Verify ESP32PartitionAnalyzer flags unencrypted NVS and missing OTA rollback."""
    raw_data = _build_synthetic_unified_flash()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
        tmp.write(raw_data)
        tmp_path = tmp.name

    try:
        extractor = ESP32Extractor()
        firmware_map = extractor.extract(tmp_path)

        analyzer = ESP32PartitionAnalyzer()
        findings = analyzer.run_with_map(tmp_path, firmware_map)

        assert isinstance(findings, list)
        finding_ids = [f.id for f in findings]

        # Expect FIRM-ESP32-PART-030 (unencrypted NVS)
        assert "FIRM-ESP32-PART-030" in finding_ids

        # Expect FIRM-ESP32-PART-055 (single factory partition without OTA)
        assert "FIRM-ESP32-PART-055" in finding_ids
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)