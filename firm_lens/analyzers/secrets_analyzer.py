import math
import re
from typing import List, Dict, Any
from firm_lens.utils.string_extractor import StringExtractor
from firm_lens.utils.findings import Finding

class SecretsAnalyzer:
    """Identifies static key material and high-entropy credential escrow."""
    def __init__(self):
        self.extractor = StringExtractor(min_length=16)
        self.pem_markers = [
            b"BEGIN RSA PRIVATE KEY", b"BEGIN EC PRIVATE KEY",
            b"BEGIN PRIVATE KEY", b"BEGIN ENCRYPTED PRIVATE KEY"
        ]
        self.c_code_junk = {"ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", "0123456789"}

    def run_with_map(self, firmware_path: str, firmware_map: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        raw_data = firmware_map.get("raw_binary", b"")
        if not raw_data: 
            return findings

        for marker in self.pem_markers:
            offset = 0
            while True:
                offset = raw_data.find(marker, offset)
                if offset == -1: 
                    break
                findings.append(Finding(
                    id="FL-CRED-PRIVATEKEY",
                    title="Cryptographic Material Isolated",
                    evidence=marker.decode('ascii', errors='ignore'),
                    offset=hex(offset)
                ))
                offset += len(marker)

        try:
            strings = self.extractor.extract_from_bytes(raw_data)
            for offset, found_str in strings:
                clean_str = re.sub(r'[^\x20-\x7E]', '', found_str).strip()
                
                # Filter format strings
                if "%s" in clean_str or "%d" in clean_str or "%x" in clean_str.lower():
                    continue
                
                # Increased entropy threshold for O-1 accuracy (4.5 is very high confidence for 16+ chars)
                if len(clean_str) >= 16 and self._calculate_shannon_entropy(clean_str) > 4.5:
                    if any(junk in clean_str for junk in self.c_code_junk):
                        continue
                    
                    # Strict validation for Base64 or Hex
                    is_base64 = bool(re.match(r'^[A-Za-z0-9+/]+={0,2}$', clean_str))
                    is_hex = bool(re.match(r'^[A-Fa-f0-9]+$', clean_str))
                    
                    if is_base64 or is_hex:
                        findings.append(Finding(
                            id="FL-CRED-HIGHENTROPY",
                            title="High Entropy Cryptographic Token",
                            evidence=f"{clean_str} (Base64/Hex)",
                            offset=hex(offset)
                        ))
        except Exception:
            pass
        return findings

    def _calculate_shannon_entropy(self, text: str) -> float:
        if not text: return 0.0
        frequencies = {}
        for char in text: 
            frequencies[char] = frequencies.get(char, 0) + 1
        entropy = 0.0
        for count in frequencies.values():
            p = count / len(text)
            entropy -= p * math.log2(p)
        return entropy

    def run(self, firmware_path: str) -> List[Finding]: 
        return []