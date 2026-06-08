import re
from typing import List, Dict, Any
from firm_lens.utils.string_extractor import StringExtractor
from firm_lens.utils.findings import Finding

class CryptoAnalyzer:
    """Cryptographic Primitive Configuration Profile Sensor."""

    def __init__(self):
        self.extractor = StringExtractor(min_length=3)
        self.patterns = {
            "MD5": re.compile(r"\bMD5\b", re.IGNORECASE),
            "AES": re.compile(r"\bAES\b", re.IGNORECASE)
        }

    def run_with_map(self, firmware_path: str, firmware_map: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        raw_data = firmware_map.get("raw_binary", b"")

        if not raw_data:
            return findings

        try:
            strings = self.extractor.extract_from_bytes(raw_data)
            for offset, found_str in strings:
                for algo, rx in self.patterns.items():
                    if rx.search(found_str):
                        findings.append(Finding(
                            id="FL-CIPH-WEAK",
                            evidence=f"Primitive string instruction match: '{found_str}'",
                            offset=hex(offset)
                        ))
        except Exception:
            pass

        return findings

    def run(self, firmware_path: str) -> List[Finding]:
        return []
