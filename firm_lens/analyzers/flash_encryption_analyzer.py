import math
import re
from typing import List, Dict, Any
from firm_lens.utils.findings import Finding

class FlashEncryptionAnalyzer:
    """Data-at-Rest Storage Cryptography Obfuscation Sensor."""

    def run_with_map(self, firmware_path: str, firmware_map: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        raw_data = firmware_map.get("raw_binary", b"")

        if not raw_data:
            return findings

        try:
            # Byte-level regex to rip out any contiguous block of 256+ empty bytes.
            clean_data = re.sub(b'\xff{256,}', b'', raw_data)
            
            # Fallback in case the binary was entirely empty flash
            if not clean_data:
                clean_data = raw_data

            frequencies = [0] * 256
            for byte in clean_data:
                frequencies[byte] += 1
                
            entropy = 0.0
            total_bytes = len(clean_data)
            for count in frequencies:
                if count == 0: continue
                p = count / total_bytes
                entropy -= p * math.log2(p)
                
            is_encrypted = entropy >= 7.85
            density_percentage = (entropy / 8.0) * 100.0 

            if not is_encrypted:
                findings.append(Finding(
                    id="FL-HARD-ENCRYPTION",
                    evidence=f"Active Payload Entropy: {entropy:.4f} (Density: {density_percentage:.2f}%). Threshold for hardware encryption is 7.85.",
                    offset="Global System Metric"
                ))

        except Exception:
            pass

        return findings

    def run(self, firmware_path: str) -> List[Finding]:
        return []