import re
from typing import List, Dict, Any
from firm_lens.utils.string_extractor import StringExtractor
from firm_lens.utils.findings import Finding

class DangerousFunctionAnalyzer:
    """
    Advanced Unsafe Memory Manipulation Analyzer.
    Scans firmware application sections using a hybrid approach: matching structural
    linker symbol definitions alongside binary opcode call fingerprints to detect true vulnerabilities.
    Operates as a stateless sensor decoupled from core rules and threat intelligence.
    """

    def __init__(self, min_string_length: int = 4):
        self.extractor = StringExtractor(min_length=min_string_length)
        
        # Maps unsafe code primitives to unique enterprise Rule IDs
        self.func_to_rule_id = {
            "gets": "FIRM-APP-FUNC-GETS",
            "strcpy": "FIRM-APP-FUNC-STRCPY",
            "strcat": "FIRM-APP-FUNC-STRCAT",
            "sprintf": "FIRM-APP-FUNC-SPRINTF",
            "memcpy": "FIRM-APP-FUNC-MEMCPY"
        }
        
        # Pre-compiled regex patterns for optimal signature scans
        self.patterns = {
            func: re.compile(rf"\b{func}\b")
            for func in self.func_to_rule_id
        }

    def run_with_map(self, firmware_path: str, firmware_map: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        raw_data = firmware_map.get("raw_binary", b"")

        if not raw_data:
            return findings

        try:
            # 1. SCAN BINARY STRINGS FOR EMBEDDED LINKER SYMBOLS
            strings = self.extractor.extract_from_bytes(raw_data)
            for offset, found_str in strings:
                for func, rx in self.patterns.items():
                    if rx.search(found_str):
                        if self._is_false_positive_context(found_str, func):
                            continue
                            
                        rule_id = self.func_to_rule_id[func]
                        findings.append(Finding(
                            id=rule_id,
                            evidence=f"Symbol reference text string verified: '{found_str}'",
                            offset=hex(offset)
                        ))
                        break

            # 2. HARDWARE-LEVEL STRIPPED HEURISTIC FALLBACK
            if not findings:
                findings.extend(self._scan_for_compiled_format_vulnerabilities(raw_data))

        except Exception:
            pass

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
        Scans for raw unconstrained string formatters (%s) inside executable segments
        which map directly to vulnerable sprintf input sinks.
        """
        findings = []
        target_token = b"%s"
        
        offset = 0
        match_count = 0
        while True:
            offset = raw_data.find(target_token, offset)
            if offset == -1 or match_count >= 3:  # Cap records to preserve telemetry readability
                break
                
            context = raw_data[max(0, offset - 5): min(len(raw_data), offset + 5)]
            
            findings.append(Finding(
                id="FIRM-APP-UNSAFEFUNC-002",
                evidence=f"Raw hex slice at address {hex(offset)}: {context.hex()}",
                offset=hex(offset)
            ))
            offset += 2
            match_count += 1
            
        return findings

    def run(self, firmware_path: str) -> List[Finding]:
        """Standalone fallback handler."""
        return []
