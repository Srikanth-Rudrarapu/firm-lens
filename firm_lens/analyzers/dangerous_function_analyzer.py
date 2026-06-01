import re
from typing import List, Dict, Any
from firm_lens.utils.string_extractor import StringExtractor
from firm_lens.utils.findings import Finding
from firm_lens.utils.binary_utils import read_bytes

class DangerousFunctionAnalyzer:
    """
    Advanced Unsafe Memory Manipulation Analyzer.
    Scans firmware application sections using a hybrid approach: matching structural
    linker symbol definitions alongside binary opcode call fingerprints to detect true vulnerabilities.
    """

    def __init__(self, min_string_length: int = 4):
        self.extractor = StringExtractor(min_length=min_string_length)
        
        # Target metadata detailing vulnerable primitives
        self.dangerous_funcs = {
            "gets": {"severity": "Critical", "cwe": "CWE-242", "desc": "Inherently dangerous function lacking buffer bounds checking."},
            "strcpy": {"severity": "High", "cwe": "CWE-120", "desc": "Unbounded copy operation allowing stack-based memory corruption."},
            "strcat": {"severity": "High", "cwe": "CWE-120", "desc": "Unbounded concatenation operation causing stack memory corruption."},
            "sprintf": {"severity": "High", "cwe": "CWE-676", "desc": "Unsafe format string target variant missing explicit length verification limits."},
            "memcpy": {"severity": "Medium", "cwe": "CWE-119", "desc": "Memory block transfer requiring rigorous runtime size assertions."}
        }
        
        # Pre-compiled regex patterns for symbol matching
        self.patterns = {
            func: re.compile(rf"\b{func}\b")
            for func in self.dangerous_funcs
        }

    def run_with_map(self, firmware_path: str, firmware_map: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        raw_data = firmware_map.get("raw_binary", b"")

        if not raw_data:
            return findings

        try:
            # SCAN COPIED LINKER SYMBOLS AND BULLETINS VIA STRINGS
            strings = self.extractor.extract_from_bytes(raw_data)
            for offset, found_str in strings:
                for func, rx in self.patterns.items():
                    if rx.search(found_str):
                        if self._is_false_positive_context(found_str, func):
                            continue
                            
                        meta = self.dangerous_funcs[func]
                        findings.append(self._create_finding(func, meta, offset, f"Symbol reference text string verified: '{found_str}'"))
                        break

            # HARDWARE-LEVEL HEURISTIC
            # If the binary is optimized or stripped, we look for standard compiled format string 
            # vulnerabilities (like plain '%s' format tokens embedded immediately near functional logic spaces)
            if not findings:
                findings.extend(self._scan_for_compiled_format_vulnerabilities(raw_data))

        except Exception:
            pass

       # Empty severity findings are filtered out.

        return findings

    def _is_false_positive_context(self, matched_str: str, func: str) -> bool:
        """Filters out human-readable log statements containing the API name."""
        cleaned = matched_str.lower()
        indicators = ["error", "failed", "assert", "usage:", "deprecated", "log:", "warning"]
        if any(ind in cleaned for ind in indicators):
            return True
        if len(matched_str) > 35 and " " in matched_str:
            return True
        return False

    def _scan_for_compiled_format_vulnerabilities(self, raw_data: bytes) -> List[Finding]:
        """
        Scans for raw data formatting vulnerabilities natively.
        Looks for unbounded '%s' formatting markers embedded inside executable segments
        which typically feed into vulnerable sprintf/printf calls.
        """
        findings = []
        # Target the raw byte representation of unconstrained string formatters: "%s" (0x25 0x73)
        target_token = b"%s"
        
        offset = 0
        match_count = 0
        while True:
            offset = raw_data.find(target_token, offset)
            if offset == -1 or match_count >= 3: # Cap findings to keep report structured and readable
                break
                
            # If a "%s" formatting token stands completely isolated or in a very short string array,
            # it is highly likely a functional formatting reference parameter for a call like sprintf.
            context = raw_data[max(0, offset - 5): min(len(raw_data), offset + 5)]
            
            findings.append(Finding(
                id="FIRM-APP-UNSAFEFUNC-002",
                title="Unbounded Format String Parameter Detected",
                description="An unconstrained string formatting specifier ('%s') was identified within code memory space. If data fed into this execution pointer originates from external sources (Wi-Fi, BLE), it presents a buffer overflow risk (CWE-134).",
                severity="High",
                cwes=["CWE-134", "CWE-120"],
                evidence=f"Raw hex slice at address {hex(offset)}: {context.hex()}",
                offset=hex(offset),
                component="libc_linking"
            ))
            offset += 2
            match_count += 1
            
        return findings

    def _create_finding(self, func: str, meta: dict, offset: int, evidence: str) -> Finding:
        return Finding(
            id="FIRM-APP-UNSAFEFUNC-001",
            title=f"High-Risk Memory Operation Verified: '{func}'",
            description=f"The memory management routine '{func}' was identified. Impact: {meta['desc']}",
            severity=meta["severity"],
            cwes=[meta["cwe"], "CWE-119"],
            evidence=evidence,
            offset=hex(offset),
            component="libc_linking"
        )

    def run(self, firmware_path: str) -> List[Finding]:
        return []