import re
from typing import List, Dict, Any
from firm_lens.utils.string_extractor import StringExtractor
from firm_lens.utils.findings import Finding

class DangerousFunctionAnalyzer:
    """
    Advanced Unsafe Function Analyzer.
    Scans firmware boundaries for high-risk C standard library linking symbols.
    """

    def __init__(self, min_string_length: int = 4):
        self.extractor = StringExtractor(min_length=min_string_length)
        self.dangerous_funcs = [
            "strcpy", "strncpy", "sprintf", "vsprintf", "gets", 
            "scanf", "sscanf", "memcpy", "memmove", "strcat", 
            "strncat", "system", "popen", "exec", "malloc"
        ]
        self.patterns = [
            re.compile(rf"\b{func}\b")
            for func in self.dangerous_funcs
        ]

    def run_with_map(self, firmware_path: str, firmware_map: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        raw_data = firmware_map.get("raw_binary", b"")

        if not raw_data:
            return findings

        try:
            strings = self.extractor.extract_from_bytes(raw_data)
            for offset, s in strings:
                self._check_function_match(offset, s, findings)
        except Exception:
            pass

        return findings

    def _check_function_match(self, addr: int, s: str, findings: List[Finding]):
        addr_str = hex(addr) if isinstance(addr, int) else str(addr)
        for rx in self.patterns:
            m = rx.search(s)
            if m:
                func = m.group(0)
                findings.append(
                    Finding(
                        id="FIRM-APP-UNSAFEFUNC-001",
                        title=f"Banned or Unsafe Function Symbol Detected: '{func}'",
                        description=(
                            f"The native memory management code symbol reference '{func}' was parsed in memory. "
                            "This confirms that the application layers rely on unsafe legacy libc routines "
                            "highly vulnerable to memory corruption attacks like stack-based buffer overflows (CWE-120)."
                        ),
                        severity=self._severity_for(func),
                        cwes=["CWE-120", "CWE-119", "CWE-676"],
                        evidence=f"Symbol reference string: '{func}'",
                        offset=addr_str,
                        component="libc_linking",
                    )
                )
                break

    def _severity_for(self, func: str) -> str:
        critical = {"gets", "strcpy", "system", "exec"}
        high = {"sprintf", "strcat", "popen", "scanf"}
        if func in critical: return "Critical"
        if func in high: return "High"
        return "Medium"

    def run(self, firmware_path: str) -> List[Finding]:
        return []