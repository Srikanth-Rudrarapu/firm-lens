from typing import List
from firm_lens.utils.findings import Finding


class CryptoAnalyzer:
    """
    Signatureless Cryptographic Algorithm Analyzer.
    Scans compiled instruction blocks for mathematically rigid initialization vectors
    and constant matrices representing specific cryptographic primitives.
    """

    # Real-world cryptographically fixed constant arrays found in compiled binaries
    CRYPTO_CONSTANTS = {
        "MD5_State_Matrix": {
            # Standard MD5 buffer initial state values in Little-Endian format
            "sig": b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10",
            "title": "MD5 Broken Hash Algorithm Architecture",
            "cwes": ["CWE-327", "CWE-328"],
            "severity": "High",
            "desc": "The MD5 initialization vector matrix was identified in the binary layout. MD5 is cryptographically broken and highly vulnerable to collision attacks."
        },
        "SHA1_State_Matrix": {
            # Standard SHA-1 initial hash values (H0 through H4)
            "sig": b"\x67\x45\x23\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x10\x32\x54\x76\xc3\xd2\xe1\xf0",
            "title": "SHA-1 Weak Hash Algorithm Architecture",
            "cwes": ["CWE-327", "CWE-328"],
            "severity": "Medium",
            "desc": "SHA-1 structural constant signatures were isolated. SHA-1 is no longer secure against well-funded cryptographic collision vectors."
        },
        "AES_Rijndael_SBox": {
            # The first 16 bytes of the standard AES encryption S-box configuration array
            "sig": b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5\x30\x01\x67\x2b\xfe\xd7\xab\x76",
            "title": "AES Cipher Block Engine Discovered",
            "cwes": [],
            "severity": "Info",
            "desc": "Standard Rijndael S-Box definitions were identified. This confirms the presence of active AES encryption layers."
        }
    }

    def run(self, firmware_path: str) -> List[Finding]:
        findings: List[Finding] = []

        try:
            with open(firmware_path, "rb") as f:
                data = f.read()
        except Exception:
            return findings

        # Scan raw data space directly for real mathematical signatures
        for algo_key, meta in self.CRYPTO_CONSTANTS.items():
            start = 0
            while True:
                idx = data.find(meta["sig"], start)
                if idx == -1:
                    break

                findings.append(
                    Finding(
                        id="FIRM-CRYPTO-002",
                        title=meta["title"],
                        description=meta["desc"],
                        severity=meta["severity"],
                        cwes=meta["cwes"],
                        evidence=f"Matched cryptographic engine footprint at offset {hex(idx)}",
                        offset=hex(idx),
                        component="crypto_engine",
                    )
                )
                start = idx + 1

         # Empty severity findings are filtered out.

        return findings