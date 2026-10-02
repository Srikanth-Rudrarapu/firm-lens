import re
from typing import List
from firm_lens.utils.findings import Finding

class FingerprintAnalyzer:
    """SDK & Library Fingerprinting Engine."""
    def __init__(self):
        self.sdk_patterns = {
            "ESP-IDF": re.compile(rb"esp-idf-v(\d+\.\d+\.\d+)"),
            "MbedTLS": re.compile(rb"mbed TLS (\d+\.\d+\.\d+)"),
            "FreeRTOS": re.compile(rb"FreeRTOS V(\d+\.\d+\.\d+)"),
            "Arduino-ESP32": re.compile(rb"arduino-esp32-(\d+\.\d+\.\d+)")
        }

    def run(self, firmware_path: str) -> List[Finding]:
        findings = []
        try:
            with open(firmware_path, "rb") as f: content = f.read()
            for sdk_name, pattern in self.sdk_patterns.items():
                match = pattern.search(content)
                if match:
                    version = match.group(1).decode()
                    findings.append(Finding(
                        id="FL-FINGER-SDK",
                        evidence=f"Discovered via SBOM version fingerprint matching: {sdk_name} v{version}",
                        offset=hex(match.start())
                    ))
        except Exception:
            pass
        return findings
