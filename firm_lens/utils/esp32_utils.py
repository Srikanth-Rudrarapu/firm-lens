import struct
import os


class ESP32FirmwareParser:
    """
    Realistic ESP32 firmware parser used by FirmLens analyzers.

    Supports:
      • Bootloader header parsing
      • Application header parsing
      • Partition table parsing (critical for real-world analysis)
      • Safe, bounds-checked binary reads

    This parser does NOT emulate flash layout — it reads raw bytes from
    the firmware image exactly as provided.
    """

    BOOTLOADER_OFFSET = 0x1000
    PARTITION_TABLE_OFFSET = 0x8000
    APP_OFFSET = 0x10000

    IMAGE_HEADER_FORMAT = "<BBBBI"  # magic, segment_count, spi_mode, spi_speed_size, entry_addr
    PARTITION_ENTRY_FORMAT = "<II16s16s"  # type, subtype, offset, size, label, flags
    PARTITION_ENTRY_SIZE = struct.calcsize(PARTITION_ENTRY_FORMAT)

    def __init__(self, firmware_path: str):
        self.firmware_path = firmware_path

    # ------------------------------------------------------------
    # Safe binary reader
    # ------------------------------------------------------------
    def _read(self, offset: int, length: int) -> bytes:
        if offset < 0 or length <= 0:
            return b""

        if not os.path.exists(self.firmware_path):
            return b""

        try:
            with open(self.firmware_path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()

                if offset >= size:
                    return b""

                safe_len = min(length, size - offset)
                f.seek(offset)
                return f.read(safe_len)
        except Exception:
            return b""

    # ------------------------------------------------------------
    # ESP32 Image Header Parsing
    # ------------------------------------------------------------
    def parse_image_header(self, offset: int):
        header_size = struct.calcsize(self.IMAGE_HEADER_FORMAT)
        data = self._read(offset, header_size)

        if len(data) != header_size:
            raise ValueError(f"Incomplete ESP32 image header at offset 0x{offset:X}")

        magic, seg_count, spi_mode, spi_speed_size, entry_addr = struct.unpack(
            self.IMAGE_HEADER_FORMAT, data
        )

        return {
            "magic": magic,
            "segment_count": seg_count,
            "spi_mode": spi_mode,
            "spi_speed_size": spi_speed_size,
            "entry_addr": hex(entry_addr),
        }

    def parse_bootloader_header(self):
        return self.parse_image_header(self.BOOTLOADER_OFFSET)

    def parse_app_header(self):
        return self.parse_image_header(self.APP_OFFSET)

    # ------------------------------------------------------------
    # Partition Table Parsing
    # ------------------------------------------------------------
    def parse_partition_table(self):
        """
        Parses the ESP32 partition table at offset 0x8000.

        Each entry is 32 bytes:
            type (1 byte)
            subtype (1 byte)
            offset (4 bytes)
            size (4 bytes)
            label (16 bytes)
            flags (4 bytes)

        Stops when:
            • entry is all 0xFF (end marker)
            • entry is all 0x00 (empty)
            • invalid entry encountered
        """

        entries = []
        offset = self.PARTITION_TABLE_OFFSET

        while True:
            raw = self._read(offset, self.PARTITION_ENTRY_SIZE)
            if len(raw) != self.PARTITION_ENTRY_SIZE:
                break

            # End markers
            if raw == b"\xFF" * self.PARTITION_ENTRY_SIZE:
                break
            if raw == b"\x00" * self.PARTITION_ENTRY_SIZE:
                break

            try:
                p_type, p_subtype, p_offset, p_size, label_raw, flags = struct.unpack(
                    self.PARTITION_ENTRY_FORMAT, raw
                )
            except struct.error:
                break

            label = label_raw.split(b"\x00")[0].decode("ascii", errors="ignore")

            entries.append(
                {
                    "type": self._decode_type(p_type),
                    "subtype": p_subtype,
                    "offset": p_offset,
                    "size": p_size,
                    "label": label,
                    "flags": flags,
                }
            )

            offset += self.PARTITION_ENTRY_SIZE

        return entries

    # ------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------
    @staticmethod
    def _decode_type(t: int) -> str:
        """
        Convert ESP32 partition type byte to human-readable string.
        """
        mapping = {
            0x00: "app",
            0x01: "data",
        }
        return mapping.get(t, f"unknown_{t}")
