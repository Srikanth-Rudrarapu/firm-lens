import re
from typing import List
from firm_lens.utils.findings import Finding

class FingerprintAnalyzer:
    """
    Industrial-grade SDK & Library Fingerprinting Engine.
    Identifies build environments and third-party dependencies.
    """
    def __init__(self):
        self.sdk_patterns = {
            "ESP-IDF": re.compile(rb"esp-idf-v(\d+\.\d+\.\d+)"),
            "MbedTLS": re.compile(rb"mbed TLS (\d+\.\d+\.\d+)"),
            "FreeRTOS": re.compile(rb"FreeRTOS V(\d+\.\d+\.\d+)"),
            "Arduino-ESP32": re.compile(rb"arduino-esp32-(\d+\.\d+\.\d+)")
        }

    def run(self, firmware_path: str) -> List[Finding]:
        findings = []
        with open(firmware_path, "rb") as f:
            content = f.read()

        for sdk_name, pattern in self.sdk_patterns.items():
            match = pattern.search(content)
            if match:
                version = match.group(1).decode()
                findings.append(Finding(
                    id="FIRM-FINGER-001",
                    title=f"Detected {sdk_name} SDK",
                    description=f"Identified {sdk_name} version {version}. This allows for CVE cross-referencing.",
                    severity="Info",
                    cwes=[],  # Fingerprinting is informational
                    evidence=f"Match: {match.group(0).decode()}",
                    offset=match.start(),
                    component="metadata"
                ))
        return findings