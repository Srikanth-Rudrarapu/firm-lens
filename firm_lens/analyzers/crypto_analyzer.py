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
                clean_str = found_str.strip()
                
                # 1. Block standard ESP-IDF networking and system error logs
                noise_filter = re.compile(r'(?i)(error|invalid|function|internal|idf|must be|disable|digest|username|setting|adapter|coexist)')
                if noise_filter.search(clean_str):
                    continue

                # 2. Extract and clean the actual Cipher Suite
                for algo, rx in self.patterns.items():
                    if rx.search(clean_str):
                        clean_suite = re.sub(r'^[^a-zA-Z0-9]+', '', clean_str)
                        clean_suite = re.sub(r'(?i)^DEK-Info:\s*', '', clean_suite).strip(',;.')
                        
                        if not re.match(r'^[a-zA-Z0-9\-\s_]+$', clean_suite):
                            continue
                        
                        if len(clean_suite) > 4:
                            findings.append(Finding(
                                id="FL-CIPH-WEAK",
                                evidence=f"Cipher Suite Context: {clean_suite}",
                                offset=hex(offset)
                            ))
                        break
        except Exception:
            pass

        return findings

    def run(self, firmware_path: str) -> List[Finding]:
        return []
