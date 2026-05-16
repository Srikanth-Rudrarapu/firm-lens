import re
import os
from typing import List, Dict, Any
from firm_lens.utils.string_extractor import StringExtractor
from firm_lens.utils.findings import Finding

class AppStringAnalyzer:
    """Advanced Static Analysis (SAST) for Firmware Strings."""

    def __init__(self, min_string_length: int = 4):
        self.extractor = StringExtractor(min_length=min_string_length)
        self._patterns = {
            "hardcoded_secrets": [
                re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*[^,\s]{4,}"),
                re.compile(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*[^,\s]{8,}"),
            ],
            "jwt": [re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}")],
            "url": [re.compile(r"https?://[a-zA-Z0-9._:/\-?&=%]+")],
            "private_key": [re.compile(r"-----BEGIN (RSA|EC|PRIVATE) KEY-----")],
            "debug": [re.compile(r"(?i)(debug mode|test build|dev build|godmode)")],
        }

    def run(self, firmware_map: Any) -> List[Finding]:
        findings: List[Finding] = []
        
        # Fallback to direct file streaming if context map is missing
        if isinstance(firmware_map, str):
            if not os.path.exists(firmware_map): return []
            with open(firmware_map, "rb") as f:
                strings = self.extractor.extract_from_bytes(f.read())
            for offset, s in strings:
                self._match_patterns(offset, s, findings)
            return findings

        for segment in firmware_map.get("segments", []):
            segment_data = segment.get("data", b"")
            load_addr = segment.get("addr", "0x0")
            strings = self.extractor.extract_from_bytes(segment_data)

            for offset, s in strings:
                relative_offset = int(load_addr, 16) + offset
                self._match_patterns(relative_offset, s, findings)
        return findings

    def _match_patterns(self, offset: int, s: str, findings: List[Finding]):
        for rx in self._patterns["private_key"]:
            if rx.search(s):
                findings.append(Finding(
                    id="FIRM-APP-KEY-001",
                    title="Private key marker found in firmware",
                    description="An embedded cryptographic key signature block was parsed inside the image.",
                    severity="Critical",
                    cwes=["CWE-321", "CWE-327"],
                    evidence=s[:120],
                    offset=hex(offset) if isinstance(offset, int) else str(offset),
                    component="app_memory"
                ))
                return

        for rx in self._patterns["hardcoded_secrets"]:
            if rx.search(s):
                findings.append(Finding(
                    id="FIRM-APP-SECRET-001",
                    title="Potential hardcoded secret",
                    description="Strings matching sensitive credential criteria discovered in application plaintext strings.",
                    severity="High",
                    cwes=["CWE-798"],
                    evidence=s[:120],
                    offset=hex(offset) if isinstance(offset, int) else str(offset),
                    component="app_memory"
                ))

        for rx in self._patterns["url"]:
            m = rx.search(s)
            if m:
                url = m.group(0)
                is_insecure = url.startswith("http://")
                findings.append(Finding(
                    id="FIRM-APP-URL-001",
                    title="Insecure Endpoint Found" if is_insecure else "App Endpoint Found",
                    description="Hardcoded target server API endpoint detected inside binary fields.",
                    severity="High" if is_insecure else "Medium",
                    cwes=["CWE-319"] if is_insecure else [],
                    evidence=url,
                    offset=hex(offset) if isinstance(offset, int) else str(offset),
                    component="app_memory"
                ))