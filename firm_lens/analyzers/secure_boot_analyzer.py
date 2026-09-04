import struct
from typing import List, Dict, Any
from firm_lens.utils.findings import Finding

class SecureBootAnalyzer:
    """Hardware-Rooted Secure Boot Integrity Assessment Sensor."""

    def run_with_map(self, firmware_path: str, firmware_map: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        raw_data = firmware_map.get("raw_binary", b"")

        if not raw_data or len(raw_data) < 0x100:
            return findings

        try:
            # Check both 0x0000 (app image) and 0x1000 (full flash dump bootloader)
            valid_header_offset = None
            for candidate_offset in [0x0000, 0x1000]:
                if len(raw_data) >= candidate_offset + 4:
                    magic_byte, segment_count = struct.unpack("<BB", raw_data[candidate_offset : candidate_offset + 2])
                    if magic_byte == 0xE9:
                        valid_header_offset = candidate_offset
                        findings.append(Finding(
                            id="FL-BOOT-HEADER",
                            evidence=f"ESP32 Image Header Verified at {hex(candidate_offset)} -> Magic Byte: {hex(magic_byte)} | Active Segments: {segment_count}",
                            offset=hex(candidate_offset)
                        ))
                        break

            # Analyze Secure Boot Signature presence
            image_length = len(raw_data)
            has_sbv2_sig = False

            # Standard Secure Boot V2 signature sector magic (0xE7) check across image trailer
            trailer_offset = max(0, image_length - 4096)
            signature_block = raw_data[trailer_offset:]

            if b"\xe7" in signature_block[:16]:
                has_sbv2_sig = True

            if not has_sbv2_sig:
                findings.append(Finding(
                    id="FL-BOOT-SIGNATURE",
                    evidence=f"Signature Block Analysis: No hardware-rooted Secure Boot (V2 0xE7) signature sector discovered in image trailer (evaluated at {hex(trailer_offset)}).",
                    offset=hex(trailer_offset)
                ))

        except Exception:
            pass

        return findings

    def run(self, firmware_path: str) -> List[Finding]:
        return []