import re
from typing import List, Tuple

class StringExtractor:
    """
    Industrial-grade High-Performance String Carving Engine.
    Leverages an optimized regular expression execution matrix to extract 
    printable ASCII streams and apply semantic squelching for IoT SDKs.
    """

    def __init__(self, min_length: int = 4):
        self.min_length = min_length
        self.pattern = re.compile(rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}')
        
        # Semantic Noise Filters: Drop known ESP-IDF SDK artifacts
        self.noise_filters = [
            re.compile(r'(?i)/IDF/components/|esp-idf|/host/bluedroid|mbedtls'), # SDK Paths
            re.compile(r'\.[ch](pp)?$', re.IGNORECASE),                           # C/C++ Source file references
            re.compile(r'^[EWI] \(\d+\) [a-zA-Z0-9_-]+:'),                        # ESP_LOG debug prefixes
            re.compile(r'^(?:[a-zA-Z_]\w*::)*[a-zA-Z_]\w*\s*\('),                 # Function calls e.g., esp_wifi_init(
            re.compile(r'^TLS-[A-Z0-9-]+$|^AES-[0-9]+-[A-Z]+'),                   # TLS/Crypto Cipher Suite names
            re.compile(r'^[A-Z0-9_]{10,}$')                                       # Long ALL_CAPS macros
        ]

    def _is_semantic_noise(self, text: str) -> bool:
        """Evaluates if a string is known SDK/Compiler noise."""
        for noise_pattern in self.noise_filters:
            if noise_pattern.search(text):
                return True
        return False

    def extract_from_bytes(self, data: bytes) -> List[Tuple[int, str]]:
        if not data or not isinstance(data, (bytes, bytearray)):
            return []

        findings: List[Tuple[int, str]] = []
        
        for match in self.pattern.finditer(data):
            match_bytes = match.group()
            
            # Avoid decoding logic on repetitive padding bytes (e.g., \x20\x20\x20\x20)
            if len(match_bytes) > 64 and len(set(match_bytes)) < 4:
                continue
                
            try:
                decoded_str = match_bytes.decode("ascii", errors="ignore").strip()
                
                # Check length and apply our new noise filters
                if len(decoded_str) >= self.min_length and not self._is_semantic_noise(decoded_str):
                    findings.append((match.start(), decoded_str))
            except Exception:
                continue

        return findings