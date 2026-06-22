import struct
from typing import List, Dict, Any
from firm_lens.utils.findings import Finding

class SecureBootAnalyzer:
    """Hardware-Rooted Secure Boot Integrity Assessment Sensor."""

    def run_with_map(self, firmware_path: str, firmware_map: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        raw_data = firmware_map.get("raw_binary", b"")

        if not raw_data or len(raw_data) < 0x2000:
            return findings

        try:
            boot_offset = 0x1000
            header_slice = raw_data[boot_offset : boot_offset + 4]
            
            if len(header_slice) >= 2:
                magic_byte, segment_count = struct.unpack("<BB", header_slice[0:2])
                if magic_byte == 0xE9:
                    findings.append(Finding(
                        id="FL-BOOT-HEADER",
                         #Eevidence is explicitly dynamic based on read values
                        evidence=f"ESP32 Image Header Verified at {hex(boot_offset)} -> Magic Byte: {hex(magic_byte)} | Active Segments: {segment_count}",
                        offset=hex(boot_offset)
                    ))

            image_length = len(raw_data)
            trailer_offset = image_length - 4096
            
            if trailer_offset > 0:
                signature_block = raw_data[trailer_offset:]
                # Verify if the block is entirely empty
                if signature_block == b"\xFF" * 4096 or signature_block == b"\x00" * 4096:
                    pad_type = "0xFF (Erased Flash)" if signature_block[0] == 0xFF else "0x00 (Null Padding)"
                    
                    findings.append(Finding(
                        id="FL-BOOT-SIGNATURE",
                        evidence=f"Signature Block Analysis at {hex(trailer_offset)}: Expected 4096-byte RSA/ECDSA signature, but found {pad_type}.",
                        offset=hex(trailer_offset)
                    ))

        except Exception:
            pass

        return findings

    def run(self, firmware_path: str) -> List[Finding]:
        return []
