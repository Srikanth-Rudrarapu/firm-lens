from typing import List
from firm_lens.utils.findings import Finding


class CryptoAnalyzer:
    """
    Detects weak or deprecated cryptographic algorithms inside firmware.

    This analyzer performs a simple byte-pattern scan for known weak
    cryptographic primitives that commonly appear in embedded firmware.

    It does NOT attempt full disassembly or function-level crypto detection.
    """

    WEAK_CRYPTO = {
        b"MD5": ("MD5 Hash Detected", ["CWE-327", "CWE-328"]),
        b"SHA1": ("SHA1 Hash Detected", ["CWE-327", "CWE-328"]),
        b"DES": ("DES Cipher Detected", ["CWE-327"]),
        b"RC4": ("RC4 Cipher Detected", ["CWE-327"]),
        b"AES-ECB": ("AES in ECB Mode", ["CWE-327"]),
    }

    def run(self, firmware_path: str) -> List[Finding]:
        findings: List[Finding] = []

        # Read entire firmware into memory
        with open(firmware_path, "rb") as f:
            data = f.read()

        # Scan for weak crypto signatures
        for signature, (title, cwes) in self.WEAK_CRYPTO.items():
            start = 0
            while True:
                idx = data.find(signature, start)
                if idx == -1:
                    break

                findings.append(
                    Finding(
                        id="FIRM-CRYPTO-001",
                        title=title,
                        description="Weak or deprecated cryptographic algorithm detected.",
                        severity="High",
                        cwes=cwes,
                        evidence=signature.decode("latin1", errors="ignore"),
                        offset=idx,
                        component="firmware",
                    )
                )

                start = idx + 1

        return findings
