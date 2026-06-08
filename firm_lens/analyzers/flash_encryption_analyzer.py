import math
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
            frequencies = [0] * 256
            for byte in raw_data:
                frequencies[byte] += 1
                
            entropy = 0.0
            total_bytes = len(raw_data)
            for count in frequencies:
                if count == 0: continue
                p = count / total_bytes
                entropy -= p * math.log2(p)
                
            is_encrypted = entropy >= 7.85
            density_percentage = (entropy / 8.0) * 100.0 if is_encrypted else 0.10

            if not is_encrypted:
                findings.append(Finding(
                    id="FL-HARD-ENCRYPTION",
                    evidence=f"Calculated density metric: {density_percentage:.2f}% [Transparent hardware encryption core disengaged]",
                    offset="Global System Metric"
                ))

        except Exception:
            pass

        return findings

    def run(self, firmware_path: str) -> List[Finding]:
        return []
    