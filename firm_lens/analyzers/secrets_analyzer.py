import math
import re
from typing import List, Dict, Any
import os
from firm_lens.utils.findings import Finding

class SecretsAnalyzer:
    """
    Optimized High-Density Secrets & Key Entropy Analyzer.
    Uses a fast single-pass frequency algorithm to isolate cryptographic assets.
    """
    def __init__(self):
        # Focus on explicit target patterns that won't pollute string extractor scans
        self.signatures = {
            "WiFi SSID Marker": r"WIFI_SSID",
            "WiFi Password Marker": r"WIFI_PASS",
            "NVS Reference": r"nvs"
        }

    def _fast_entropy(self, data: bytes) -> float:
        """Calculates Shannon Entropy in a single linear pass (O(N))."""
        if not data: 
            return 0.0
        length = len(data)
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        
        entropy = 0.0
        for count in counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    def run_with_map(self, firmware_path: str, firmware_map: Dict[str, Any]) -> List[Finding]:
        findings = []
        content = firmware_map.get("raw_binary", b"")

        if not content and os.path.exists(firmware_path):
            try:
                with open(firmware_path, "rb") as f:
                    content = f.read()
            except OSError:
                pass

        if not content:
            return []

        # 1. Optimized Block Entropy Scanner (Avoids hanging on large 4MB dumps)
        window_size = 128
        step_size = 64  # Increased step to optimize performance while maintaining coverage
        
        for i in range(0, len(content) - window_size, step_size):
            window = content[i:i+window_size]
            entropy = self._fast_entropy(window)
            
            # High-density entropy check (typically indicates raw private keys or embedded binaries)
            if entropy > 7.7:  
                findings.append(Finding(
                    id="FIRM-SECRET-002",
                    title="High-Entropy Data Fragment",
                    description="Detected a localized block of high-entropy data. Likely an obfuscated key, custom token, or localized encrypted configuration structure.",
                    severity="High",
                    cwes=["CWE-312"],
                    evidence=f"Local Entropy Density: {entropy:.2f}",
                    offset=hex(i),
                    component="entropy_engine"
                ))

        # 2. Pattern Matching Signature Check
        for name, pattern in self.signatures.items():
            matches = list(re.finditer(pattern.encode(), content))
            if not matches: 
                continue

            if name == "NVS Reference" and len(matches) > 5:
                findings.append(Finding(
                    id="FIRM-SECRET-003",
                    title=f"Systemic {name} Usage Identified",
                    description=f"Identified {len(matches)} structural NVS tracking references throughout the binary image map, indicating extensive programmatic usage of Non-Volatile Storage.",
                    severity="Medium",
                    cwes=["CWE-798"],
                    evidence=f"Aggregated Count: {len(matches)} calls parsed.",
                    offset=hex(matches[0].start()),
                    component="flash_nvs"
                ))
            else:
                for match in matches:
                    findings.append(Finding(
                        id="FIRM-SECRET-001",
                        title=f"Hardcoded {name} Discovered",
                        description=f"A hardcoded compiler symbol reference matching {name} rules was detected.",
                        severity="Critical" if "Pass" in name else "Medium",
                        cwes=["CWE-798"],
                        evidence=match.group().decode(errors="ignore")[:64],
                        offset=hex(match.start()),
                        component="firmware_data"
                    ))
        return findings

    def run(self, firmware_path: str) -> List[Finding]:
        return self.run_with_map(firmware_path, {"raw_binary": b""})