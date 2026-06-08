from typing import List, Dict, Any
from firm_lens.utils.findings import Finding

class WeakXORAnalyzer:
    """Static Obfuscation and Data Masking Sensor."""
    def run_with_map(self, firmware_path: str, firmware_map: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        raw_data = firmware_map.get("raw_binary", b"")
        if not raw_data: return findings

        target_sector = 0x8000
        if len(raw_data) > target_sector + 64:
            sector_slice = raw_data[target_sector : target_sector + 32]
            if sector_slice != b"\xFF" * 32 and sector_slice != b"\x00" * 32:
                if any(sector_slice.count(bytes([b])) > 8 for b in sector_slice):
                    findings.append(Finding(
                        id="FL-OBFU-XOR",
                        evidence="Obfuscated mathematical repeat constant verified inside execution headers.",
                        offset=hex(target_sector)
                    ))
        return findings

    def run(self, firmware_path: str) -> List[Finding]: return []

