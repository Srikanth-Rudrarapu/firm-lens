import struct
import os
import subprocess
import sys

class ESP32FirmwareParser:
    """
    Realistic ESP32 firmware parser used by FirmLens analyzers.
    Provides bounds-checked, fail-safe binary processing.
    """

    def __init__(self, firmware_path: str):
        self.firmware_path = firmware_path

    def _read(self, offset: int, length: int) -> bytes:
        if offset < 0 or length <= 0 or not os.path.exists(self.firmware_path):
            return b""
        try:
            with open(self.firmware_path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                if offset >= size:
                    return b""
                
                # Reset the file cursor to the requested offset before reading
                f.seek(offset) 
                return f.read(min(length, size - offset))
        except Exception:
            return b""

    def parse_image_header(self, offset: int):
        fmt = "<BBBBI"
        header_size = struct.calcsize(fmt)
        data = self._read(offset, header_size)

        if len(data) != header_size:
            return None

        magic, seg_count, spi_mode, spi_speed_size, entry_addr = struct.unpack(fmt, data)
        return {
            "magic": magic,
            "segment_count": seg_count,
            "spi_mode": spi_mode,
            "spi_speed_size": spi_speed_size,
            "entry_addr": hex(entry_addr),
        }


class ESP32HardwareDumper:
    """
    Hardware Forensics Layer.
    Programmatically interacts with physical ESP32 chips over serial interfaces
    to extract live flash images for forensic security auditing.
    """
    
    @staticmethod
    def dump_flash(port: str, baud: int, output_path: str) -> bool:
        """
        Executes esptool dynamically to read the entire 4MB flash size 
        typical of standard ESP32 DevKit boards.
        """
        cmd = [
            sys.executable, "-m", "esptool",
            "--port", port,
            "--baud", str(baud),
            "read_flash", "0", "0x400000",
            output_path
        ]
        
        try:
            import esptool
        except ImportError:
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "esptool"])
            except Exception:
                return False

        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode == 0:
                return True
            return False
        except Exception:
            return False