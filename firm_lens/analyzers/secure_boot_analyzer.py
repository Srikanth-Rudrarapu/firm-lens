from typing import List, Dict, Any
import math
from math import log2
import os
from firm_lens.utils.findings import Finding

class SecureBootAnalyzer:
    """
    Advanced ESP32 Secure Boot Posture Analyzer.
    Evaluates hardware image configuration structures and trailing cryptographic sign offsets.
    """

    BOOTLOADER_MAX_SIZE = 0x10000      
    SIGNATURE_WINDOW_SIZE = 512        
    SIGNATURE_MIN_ENTROPY = 7.2        

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
                entropy -= p * math.log2(p)
        return entropy

    def run_with_map(self, firmware_path: str, firmware_map: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        data = firmware_map.get("raw_binary", b"")
        is_unified = firmware_map.get("is_unified_flash", False)
        
        if not data and os.path.exists(firmware_path):
            try:
                with open(firmware_path, "rb") as f:
                    data = f.read()
            except OSError:
                pass

        if not data:
            return []

        target_offset = 0x1000 if is_unified else 0x0
        target_offset_str = hex(target_offset)

        # 1. Structural Header Verification (Defensively isolated)
        try:
            from firm_lens.utils.esp32_utils import ESP32FirmwareParser
            parser = ESP32FirmwareParser(firmware_path)
            image_hdr = parser.parse_image_header(target_offset)
            
            if image_hdr and image_hdr.get("magic") in (0xE9, 0xEA):
                header_type = "Bootloader" if is_unified else "Application"
                findings.append(Finding(
                    id="FIRM-SECBOOT-002",
                    title=f"ESP32 {header_type} Header Verified",
                    description=f"Valid initialization configuration magic identified at structural base offset.",
                    severity="Info",
                    cwes=[],
                    evidence=f"Magic: {hex(image_hdr['magic'])}, Segments: {image_hdr['segment_count']}",
                    offset=target_offset_str,
                    component="header"
                ))
            else:
                findings.append(Finding(
                    id="FIRM-SECBOOT-001",
                    title="Invalid ESP32 Target Image Magic",
                    description="Missing structural header format tracking markers.",
                    severity="High",
                    cwes=["CWE-302"],
                    offset=target_offset_str,
                    component="header"
                ))
        except Exception as e:
            # Fallback block: Log the extraction parsing error as a warning context but do not crash out
            findings.append(Finding(
                id="FIRM-SECBOOT-WARNING",
                title="Hardware Structural Header Extraction Interrupted",
                description=f"The lower-level utility engine encountered an issue parsing the structural map: {str(e)}. Defaulting to raw signature sweep metrics.",
                severity="Medium",
                cwes=["CWE-665"],
                offset=target_offset_str,
                component="header"
            ))

        # 2. Cryptographic Secure Boot Signature Tail Block Verification
        try:
            if is_unified:
                bootloader_region = data[:self.BOOTLOADER_MAX_SIZE]
                if len(bootloader_region) >= self.SIGNATURE_WINDOW_SIZE:
                    sig_offset = min(len(bootloader_region), self.BOOTLOADER_MAX_SIZE) - self.SIGNATURE_WINDOW_SIZE
                    sig_region = bootloader_region[-self.SIGNATURE_WINDOW_SIZE:]
                    entropy = self._calculate_entropy(sig_region)
                    self._evaluate_entropy(entropy, findings, hex(sig_offset), "Bootloader Sector Boundary")
            else:
                if len(data) > 4096:
                    sig_offset = len(data) - 4096
                    app_tail = data[-4096:]
                    entropy = self._calculate_entropy(app_tail)
                    self._evaluate_entropy(entropy, findings, hex(sig_offset), "Application Image Margin")
        except Exception:
            pass

        return findings

    def _evaluate_entropy(self, entropy: float, findings: List[Finding], offset_str: str, context: str):
        if entropy >= self.SIGNATURE_MIN_ENTROPY:
            findings.append(Finding(
                id="FIRM-SECBOOT-020",
                title="Cryptographic Signature Block Appears Appended",
                description=f"High-entropy tail detected inside the {context}, correlating with an active Secure Boot validation block verification scheme.",
                severity="Info",
                cwes=[],
                evidence=f"Tail Entropy Density: {entropy:.2f}",
                offset=offset_str,
                component="entropy"
            ))
        else:
            findings.append(Finding(
                id="FIRM-SECBOOT-021",
                title="Missing Secure Boot Signature Sector",
                description=f"The trailing block of the {context} exhibits abnormally flat entropy. Real-world implication: Secure Boot signature parameters are entirely absent or bypassed.",
                severity="High",
                cwes=["CWE-347"],
                evidence=f"Tail Entropy: {entropy:.2f} (Expected > {self.SIGNATURE_MIN_ENTROPY})",
                offset=offset_str,
                component="entropy"
            ))

    def run(self, firmware_path: str) -> List[Finding]:
        return []