from typing import List
from firm_lens.utils.findings import Finding
import os


class FlashEncryptionAnalyzer:
    """
    Determines whether firmware appears encrypted by measuring entropy.

    Logic:
      • Encrypted firmware → high entropy (typically > 7.0)
      • Plaintext firmware → low entropy (typically < 5.0)
      • This is heuristic, not cryptographic verification.
    """

    def calculate_entropy(self, data: bytes) -> float:
        from math import log2

        if not data:
            return 0.0

        freq = [0] * 256
        for b in data:
            freq[b] += 1

        entropy = 0.0
        total = len(data)

        for count in freq:
            if count > 0:
                p = count / total
                entropy -= p * log2(p)

        return entropy

    def run(self, firmware_path: str) -> List[Finding]:
        findings: List[Finding] = []

        # File existence check
        if not os.path.exists(firmware_path):
            return [
                Finding(
                    id="FIRM-FLASH-000",
                    title="Firmware file not found",
                    description="Cannot analyze flash encryption.",
                    severity="High",
                    cwes=["CWE-311"],
                    component="flash",
                )
            ]

        # Read firmware bytes
        with open(firmware_path, "rb") as f:
            data = f.read()

        entropy = self.calculate_entropy(data)

        # Heuristic threshold
        if entropy < 5.0:
            findings.append(
                Finding(
                    id="FIRM-FLASH-001",
                    title="Firmware appears unencrypted",
                    description="Low entropy suggests firmware is stored in plaintext.",
                    severity="High",
                    cwes=["CWE-311"],
                    evidence=f"entropy={entropy:.2f}",
                    component="flash",
                )
            )
        else:
            findings.append(
                Finding(
                    id="FIRM-FLASH-002",
                    title="Firmware appears encrypted or compressed",
                    description="High entropy suggests encryption or compression.",
                    severity="Info",
                    cwes=[],
                    evidence=f"entropy={entropy:.2f}",
                    component="flash",
                )
            )

        return findings
