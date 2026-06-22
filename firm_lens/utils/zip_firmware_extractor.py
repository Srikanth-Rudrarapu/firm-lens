import os
import zipfile
import tempfile
from typing import List


class ZipFirmwareExtractor:
    """
    Safely extract firmware images and partition segments from ZIP-based update packages.

    Supports:
        - Espressif OTA deployment bundles (bootloader.bin, partition-table.bin, app.bin)
        - Monolithic flash memory layout containers and custom partition segments (*.bin, *.img, *.hex)

    Security Mitigations:
        - Path Traversal: Enforces absolute destination boundaries to prevent Zip Slip exploits.
        - Symlink Rejection: Deep-inspects and rejects soft links/symlinks inside the archive structure.
        - Resource Protection: Implements strict limits on total extracted size and maximum file count.
        - Nested Archives: Restricts execution layers by completely rejecting nested ZIP bundles.
        - Ingestion Filters: Whitelists only file extensions explicitly matching recognized firmware structures.
    """

    # Hard safety limits
    MAX_TOTAL_SIZE = 100 * 1024 * 1024  # 100 MB
    MAX_FILES = 100

    FIRMWARE_EXTENSIONS = {".bin", ".hex", ".elf", ".img"}
    FIRMWARE_KEY_NAMES = {
        "bootloader.bin",
        "app.bin",
        "partitions.bin",
        "firmware.bin",
        "fw.bin",
        "boot.img",
        "system.img",
        "kernel.img",
    }

    def _is_safe_path(self, base: str, target: str) -> bool:
        """
        Prevent Zip Slip by ensuring extracted file stays inside temp directory.
        """
        abs_base = os.path.abspath(base)
        abs_target = os.path.abspath(target)
        return abs_target.startswith(abs_base)

    def _is_symlink(self, zip_file: zipfile.ZipFile, info: zipfile.ZipInfo) -> bool:
        """
        Detect symlinks inside ZIPs (common attack vector).
        """
        return (info.external_attr >> 16) & 0o120000 == 0o120000

    def extract_firmware_files(self, zip_path: str) -> List[str]:
        if not zipfile.is_zipfile(zip_path):
            return []

        extracted_firmware: List[str] = []
        total_size = 0

        with zipfile.ZipFile(zip_path, "r") as zf:
            infos = zf.infolist()

            # Basic safety checks
            if len(infos) > self.MAX_FILES:
                return []

            with tempfile.TemporaryDirectory(prefix="firmlens_zip_") as tmpdir:
                for info in infos:
                    name_lower = os.path.basename(info.filename).lower()
                    ext = os.path.splitext(name_lower)[1]

                    # Reject nested ZIPs
                    if name_lower.endswith(".zip"):
                        continue

                    # Reject symlinks
                    if self._is_symlink(zf, info):
                        continue

                    # Skip directories
                    if info.is_dir():
                        continue

                    # Size checks
                    total_size += info.file_size
                    if total_size > self.MAX_TOTAL_SIZE:
                        break

                    # Decide if this entry looks like firmware
                    is_firmware_name = name_lower in self.FIRMWARE_KEY_NAMES
                    is_firmware_ext = ext in self.FIRMWARE_EXTENSIONS

                    if not (is_firmware_name or is_firmware_ext):
                        continue

                    # Safe extraction path
                    out_path = os.path.join(tmpdir, name_lower)

                    # Prevent Zip Slip
                    if not self._is_safe_path(tmpdir, out_path):
                        continue

                    # Extract safely
                    try:
                        with zf.open(info, "r") as src, open(out_path, "wb") as dst:
                            dst.write(src.read())
                    except Exception:
                        continue

                    extracted_firmware.append(out_path)

                return extracted_firmware
