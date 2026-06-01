import math
import re
from typing import List, Dict, Any
from firm_lens.utils.string_extractor import StringExtractor
from firm_lens.utils.findings import Finding

class SecretsAnalyzer:
    """
    Advanced Secrets and Cryptographic Key Extraction Engine.
    Scans extracted application data strings for high-entropy tokens, 
    embedded private keys, and credential assignment patterns.
    """
    def __init__(self, min_string_length: int = 4):
        self.extractor = StringExtractor(min_length=min_string_length)
        
        # Target assignments found in unstripped code or credential configs
        self.signatures = {
            "PEM_Private_Key": re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----"),
            "Generic_Secret_Assignment": re.compile(r"(?i)\b(api_key|passwd|password|secret|auth_token)\s*[:=]\s*['\"][A-Za-z0-9_\-]+['\"]")
        }

    def _calculate_string_entropy(self, text: str) -> float:
        """Calculates Shannon Entropy of a specific text string to evaluate token randomness."""
        if not text:
            return 0.0
        length = len(text)
        frequencies = {}
        for char in text:
            frequencies[char] = frequencies.get(char, 0) + 1
        
        entropy = 0.0
        for count in frequencies.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def run_with_map(self, firmware_path: str, firmware_map: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        raw_data = firmware_map.get("raw_binary", b"")

        if not raw_data:
            return findings

        try:
            # Leverage optimized string layer to bypass raw assembly instructions
            strings = self.extractor.extract_from_bytes(raw_data)
            
            high_entropy_tokens_count = 0
            first_token_offset = None

            for offset, found_str in strings:
                cleaned_str = found_str.strip()
                
                # Check 1: Explicit High-Value Key Structures
                for name, regex in self.signatures.items():
                    if regex.search(cleaned_str):
                        findings.append(Finding(
                            id="FIRM-SECRET-001",
                            title=f"Hardcoded Credential/Key Blueprint Found: '{name}'",
                            description="An explicit credential assignment format or cryptographic key header was isolated in memory.",
                            severity="Critical",
                            cwes=["CWE-798", "CWE-312"],
                            evidence=cleaned_str[:80],
                            offset=hex(offset),
                            component="firmware_data"
                        ))

                # Check 2: High-Entropy Token Isolation (Bases, Hashes, API Tokens)
                # If a short string string contains no spaces and high randomness, it's likely a token
                if 16 <= len(cleaned_str) <= 64 and " " not in cleaned_str:
                    string_entropy = self._calculate_string_entropy(cleaned_str)
                    
                    # Base64/Hex authentication structures exhibit an internal entropy > 4.5
                    if string_entropy > 4.5:
                        high_entropy_tokens_count += 1
                        if first_token_offset is None:
                            first_token_offset = offset

            # Cluster high-entropy findings to prevent report pollution
            if high_entropy_tokens_count > 0:
                findings.append(Finding(
                    id="FIRM-SECRET-002",
                    title="High-Entropy Authentication Tokens Detected",
                    description=f"Isolated {high_entropy_tokens_count} distinct high-entropy text tokens lacking space formatting. These indicate embedded API tokens, passwords, or salts.",
                    severity="High",
                    cwes=["CWE-312", "CWE-798"],
                    evidence=f"Identified {high_entropy_tokens_count} localized key targets inside string maps.",
                    offset=hex(first_token_offset) if first_token_offset else "-",
                    component="entropy_engine"
                ))

        except Exception:
            pass

        return findings

    def run(self, firmware_path: str) -> List[Finding]:
        return []