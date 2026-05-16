from typing import List
from math import log2

from firm_lens.utils.esp32_utils import ESP32FirmwareParser
from firm_lens.utils.findings import Finding


class SecureBootAnalyzer:
    """
    Advanced ESP32 secure boot posture analyzer.

    This analyzer works purely on the provided firmware image. It does NOT
    read efuse state (which lives on the chip), but it performs real, byte-level
    analysis of the bootloader region to infer:

      - Whether the image structurally looks like a valid ESP32 bootloader/app
      - Whether there are strong hints that secure boot support is present
      - Whether there is a high-entropy block at the end of the bootloader
        that looks like a signature block (common in secure-boot-enabled images)
    """

    # Heuristic constants
    BOOTLOADER_MAX_SIZE = 0x10000      # 64 KB region typically reserved for bootloader
    SIGNATURE_WINDOW_SIZE = 512        # bytes to inspect at end of bootloader region
    SIGNATURE_MIN_ENTROPY = 7.0        # high entropy suggests signature-like data

    # Simple byte signatures that often appear in secure-boot-enabled images
    SECURE_BOOT_HINTS = [
        b"secure_boot",
        b"SECURE_BOOT",
        b"esp_secure_boot",
        b"esp_secure_boot_v2",
        b"SBK",  # Secure Boot Key (generic hint)
    ]

    def _load_firmware_bytes(self, firmware_path: str) -> bytes | None:
        try:
            with open(firmware_path, "rb") as f:
                return f.read()
        except OSError:
            return None

    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0

        freq = [0] * 256
        for b in data:
            freq[b] += 1

        entropy = 0.0
        length = len(data)

        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * log2(p)

        return entropy

    def _analyze_headers(self, parser: ESP32FirmwareParser) -> List[Finding]:
        findings: List[Finding] = []

        try:
            boot_hdr = parser.parse_bootloader_header()
            app_hdr = parser.parse_app_header()
        except Exception as e:
            findings.append(
                Finding(
                    id="FIRM-SECBOOT-000",
                    title="Failed to parse ESP32 headers",
                    description=(
                        "Secure boot analysis could not be completed because the ESP32 "
                        f"bootloader or application headers could not be parsed: {e}"
                    ),
                    severity="Medium",
                    cwes=[],
                    evidence="Header parsing failed",
                    component="bootloader",
                )
            )
            return findings

        valid_magic = boot_hdr.get("magic") in (0xE9, 0xEA)
        has_segments = (
            boot_hdr.get("segment_count", 0) > 0
            and app_hdr.get("segment_count", 0) > 0
        )

        if not valid_magic or not has_segments:
            findings.append(
                Finding(
                    id="FIRM-SECBOOT-001",
                    title="ESP32 image headers appear invalid or incomplete",
                    description=(
                        "The ESP32 bootloader or application image headers appear invalid. "
                        "This may indicate tampering, corruption, or a non-standard image layout."
                    ),
                    severity="High",
                    cwes=["CWE-302"],
                    evidence=(
                        f"boot.magic={boot_hdr.get('magic')}, "
                        f"boot.seg={boot_hdr.get('segment_count')}, "
                        f"app.seg={app_hdr.get('segment_count')}"
                    ),
                    component="bootloader",
                )
            )
        else:
            findings.append(
                Finding(
                    id="FIRM-SECBOOT-002",
                    title="ESP32 image headers appear structurally valid",
                    description=(
                        "The ESP32 bootloader and application image headers appear structurally valid. "
                        "This does not guarantee secure boot is enabled, but indicates a consistent image layout."
                    ),
                    severity="Info",
                    cwes=[],
                    evidence=(
                        f"boot.magic={boot_hdr.get('magic')}, "
                        f"boot.seg={boot_hdr.get('segment_count')}, "
                        f"app.seg={app_hdr.get('segment_count')}"
                    ),
                    component="bootloader",
                )
            )

        return findings

    def _analyze_secure_boot_hints(self, data: bytes) -> List[Finding]:
        findings: List[Finding] = []

        found_hints = [hint for hint in self.SECURE_BOOT_HINTS if hint in data]

        if found_hints:
            findings.append(
                Finding(
                    id="FIRM-SECBOOT-010",
                    title="Secure boot-related strings detected in firmware",
                    description=(
                        "The firmware contains strings related to ESP32 secure boot. "
                        "This suggests that secure boot support is present in the codebase, "
                        "but does not guarantee it is enabled in production efuse configuration."
                    ),
                    severity="Info",
                    cwes=[],
                    evidence=", ".join(h.decode('latin1', errors='ignore') for h in found_hints),
                    component="bootloader",
                )
            )
        else:
            findings.append(
                Finding(
                    id="FIRM-SECBOOT-011",
                    title="No secure boot indicators found in firmware image",
                    description=(
                        "No obvious secure boot-related strings were found in the firmware image. "
                        "This may indicate that secure boot is not implemented, or that the implementation "
                        "does not expose recognizable strings in the binary."
                    ),
                    severity="Medium",
                    cwes=[],
                    evidence="No secure boot hint strings detected",
                    component="bootloader",
                )
            )

        return findings

    def _analyze_signature_like_block(self, data: bytes) -> List[Finding]:
        findings: List[Finding] = []

        if not data:
            return findings

        bootloader_region = data[: self.BOOTLOADER_MAX_SIZE]
        if len(bootloader_region) < self.SIGNATURE_WINDOW_SIZE:
            return findings

        sig_region = bootloader_region[-self.SIGNATURE_WINDOW_SIZE:]
        entropy = self._calculate_entropy(sig_region)

        if entropy >= self.SIGNATURE_MIN_ENTROPY:
            findings.append(
                Finding(
                    id="FIRM-SECBOOT-020",
                    title="High-entropy block at end of bootloader region",
                    description=(
                        "A high-entropy block was detected at the end of the bootloader region. "
                        "This is consistent with a signature or digest block used by ESP32 secure boot."
                    ),
                    severity="Info",
                    cwes=[],
                    evidence=f"entropy={entropy:.2f}, window_size={self.SIGNATURE_WINDOW_SIZE}",
                    component="bootloader",
                )
            )
        else:
            findings.append(
                Finding(
                    id="FIRM-SECBOOT-021",
                    title="No signature-like high-entropy block detected in bootloader region",
                    description=(
                        "The end of the bootloader region does not exhibit high entropy typically associated "
                        "with a cryptographic signature block. This may indicate that secure boot is not enabled."
                    ),
                    severity="Medium",
                    cwes=[],
                    evidence=f"entropy={entropy:.2f}, window_size={self.SIGNATURE_WINDOW_SIZE}",
                    component="bootloader",
                )
            )

        return findings

    def run(self, firmware_path: str) -> List[Finding]:
        findings: List[Finding] = []

        # 1) Structural header sanity via ESP32FirmwareParser
        parser = ESP32FirmwareParser(firmware_path)
        findings.extend(self._analyze_headers(parser))

        # 2) Load raw bytes for real, byte-level analysis
        data = self._load_firmware_bytes(firmware_path)
        if data is None:
            findings.append(
                Finding(
                    id="FIRM-SECBOOT-099",
                    title="Firmware file not readable",
                    description=(
                        "The firmware file could not be opened for secure boot analysis. "
                        "Check file permissions and path validity."
                    ),
                    severity="High",
                    cwes=[],
                    evidence=firmware_path,
                    component="bootloader",
                )
            )
            return findings

        # 3) Scan for secure boot-related strings
        findings.extend(self._analyze_secure_boot_hints(data))

        # 4) Inspect bootloader region for signature-like entropy
        findings.extend(self._analyze_signature_like_block(data))

        return findings
