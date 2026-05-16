import math
import re
from typing import List
from firm_lens.utils.findings import Finding

class SecretsAnalyzer:
    def __init__(self):
        self.signatures = {
            "Private Key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
            "WiFi SSID": r"WIFI_SSID",
            "WiFi Password": r"WIFI_PASS",
            "NVS Reference": r"nvs"
        }

    def calculate_entropy(self, data: bytes) -> float:
        """Calculates Shannon Entropy (0.0 to 8.0)."""
        if not data: return 0.0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def run(self, firmware_path: str) -> List[Finding]:
        findings = []
        with open(firmware_path, "rb") as f:
            content = f.read()

        # 1. High-Entropy Scanner (Industrial Grade)
        window_size = 64
        for i in range(0, len(content) - window_size, 32):
            window = content[i:i+window_size]
            entropy = self.calculate_entropy(window)
            if entropy > 7.5:  # Indicates encryption or high-density secrets
                findings.append(Finding(
                    id="FIRM-SECRET-002",
                    title="High-Entropy Data Block",
                    description="Detected a block of high-entropy data not matching common patterns. Likely an obfuscated key or encrypted segment.",
                    severity="High",
                    cwes=["CWE-311"],
                    evidence=f"Entropy: {entropy:.2f}",
                    offset=i,
                    component="firmware"
                ))

        # 2. Aggregated Signature Scanner
        for name, pattern in self.signatures.items():
            matches = list(re.finditer(pattern.encode(), content))
            if not matches: continue

            if name == "NVS Reference" and len(matches) > 5:
                # Aggregate 70+ instances into one professional finding
                findings.append(Finding(
                    id="FIRM-SECRET-003",
                    title=f"Systemic {name} Detected",
                    description=f"Identified {len(matches)} instances of {name} throughout the binary. Indicates wide use of unencrypted storage.",
                    severity="Medium",
                    cwes=["CWE-798"],
                    evidence=f"Found {len(matches)} instances",
                    offset=matches[0].start(), # Show first location
                    component="flash"
                ))
            else:
                for match in matches:
                    findings.append(Finding(
                        id="FIRM-SECRET-001",
                        title=f"Detected {name}",
                        description=f"Hardcoded {name} identified via signature matching.",
                        severity="Critical" if "Key" in name or "Pass" in name else "Medium",
                        cwes=["CWE-798", "CWE-321"],
                        evidence=match.group().decode(errors="ignore"),
                        offset=match.start(),
                        component="firmware"
                    ))
        return findings