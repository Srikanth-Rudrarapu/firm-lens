import re
from typing import List, Dict, Any

from firm_lens.utils.string_extractor import StringExtractor
from firm_lens.utils.findings import Finding
from firm_lens.utils.cwe_mapping import CWE_MAP

class DangerousFunctionAnalyzer:
    """
    Advanced Unsafe Function Analyzer.
    Scans firmware memory segments for high-risk C standard library symbols.
    """

    def __init__(self, min_string_length: int = 4):
        self.extractor = StringExtractor(min_length=min_string_length)
        
        # Extended list of functions relevant to IoT/Embedded exploitation
        self.dangerous_funcs = [
            "strcpy", "strncpy", "sprintf", "vsprintf", "gets", 
            "scanf", "sscanf", "memcpy", "memmove", "strcat", 
            "strncat", "system", "popen", "exec", "malloc"
        ]

        self.patterns = [
            re.compile(rf"\b{func}\b") # Case-sensitive is often better for symbol names
            for func in self.dangerous_funcs
        ]

    def run(self, firmware_map: Dict[str, Any]) -> List[Finding]:
        """
        Processes extracted segments to find dangerous function symbols.
        """
        findings: List[Finding] = []
        
        # Iterate through segments provided by ESP32Extractor
        for segment in firmware_map.get("segments", []):
            segment_data = segment.get("data", b"")
            load_addr = segment.get("addr", "0x0")
            
            # Static Analysis: Extract strings from the specific memory segment
            strings = self.extractor.extract_from_bytes(segment_data)

            for offset, s in strings:
                relative_addr = int(load_addr, 16) + offset
                self._check_function_match(relative_addr, s, findings)

        return findings

    def _check_function_match(self, addr: int, s: str, findings: List[Finding]):
        """Matches strings against dangerous patterns."""
        for rx in self.patterns:
            m = rx.search(s)
            if m:
                func = m.group(0)
                findings.append(
                    Finding(
                        id="FIRM-APP-UNSAFEFUNC-001",
                        title=f"Dangerous function symbol '{func}' detected",
                        description=(
                            f"The '{func}' symbol was found in application memory. "
                            "This suggests the firmware utilizes unsafe libc functions "
                            "that are highly susceptible to buffer overflows or command injection."
                        ),
                        severity=self._severity_for(func),
                        cwes=[
                            CWE_MAP.get("unsafe_functions", "CWE-120"),
                            CWE_MAP.get("unsafe_memory_ops", "CWE-119"),
                        ],
                        evidence=f"Symbol '{func}' at {hex(addr)}",
                        offset=hex(addr),
                        component="app_memory",
                    )
                )
                break

    def _severity_for(self, func: str) -> str:
        critical = {"gets", "strcpy", "system", "exec"}
        high = {"sprintf", "strcat", "popen", "scanf"}
        
        func_lower = func.lower()
        if func_lower in critical: return "Critical"
        if func_lower in high: return "High"
        return "Medium"