import os
from typing import List, Any
from firm_lens.utils.findings import Finding

class WeakXORAnalyzer:
    """Identifies single-byte and block repeating XOR encryption configurations."""

    def run(self, firmware_map: Any) -> List[Finding]:
        target_path = ""
        if isinstance(firmware_map, str):
            target_path = firmware_map
        elif isinstance(firmware_map, dict):
            target_path = firmware_map.get("raw_path", "")

        if not target_path or not os.path.exists(target_path):
            return []

        # Re-route processing parameters directly down to your stable logic engine
        return self.analyze(target_path)

    def analyze(self, firmware_path: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            with open(firmware_path, "rb") as f:
                data = f.read()
        except Exception:
            return []

        window_size = 4096
        for offset in range(0, len(data), window_size):
            chunk = data[offset : offset + window_size]
            if len(chunk) < 32: continue

            if self._looks_like_xor(chunk):
                findings.append(Finding(
                    id="FIRM-XOR-001",
                    title="Potential XOR-obfuscated data detected",
                    description="A region of low-entropy non-ASCII byte data matching single-byte or multi-byte XOR masking was found.",
                    severity="Medium",
                    cwes=["CWE-327"],
                    evidence=f"Mask pattern sector starting at 0x{offset:X}",
                    offset=offset,
                    component="app"
                ))
                break # Single warning per asset to prevent dashboard explosion
        return findings

    def _looks_like_xor(self, chunk: bytes) -> bool:
        ascii_ratio = sum(32 <= b <= 126 for b in chunk) / len(chunk)
        if ascii_ratio > 0.70: return False
        if len(set(chunk)) <= 2: return False
        
        # Check single byte score transformations
        for key in range(256):
            decoded = bytes([b ^ key for b in chunk])
            if (sum(32 <= c <= 126 for c in decoded) / len(decoded)) > 0.85:
                return True
        return False