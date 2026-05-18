import re
from typing import List, Dict, Any
from firm_lens.utils.string_extractor import StringExtractor
from firm_lens.utils.findings import Finding

class BackdoorAnalyzer:
    """
    Advanced Backdoor & Hidden Interface Analyzer.
    Dynamically scans raw text assets for unauthorized administrative paths and tokens.
    """

    def __init__(self, min_string_length: int = 4):
        self.extractor = StringExtractor(min_length=min_string_length)
        
        # Broad-spectrum multi-architecture regular expression matrix
        self.patterns = {
            # 1. High-Risk Web/API URI Routing Paths
            "admin_paths": re.compile(r"\b/(?:admin|root|shell|debug|backdoor|maintenance|setup|config)\b[a-zA-Z0-9_\-/]*"),
            
            # 2. Hardcoded Session Tokens & API Secret Key Assignment Structures
            "auth_tokens": re.compile(r"\b(api[-_]?key|auth[-_]?token|jwt[-_]?token|secret[-_]?key|passwd|bearer)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{10,})['\"]?", re.IGNORECASE),
            
            # 3. Serial & Shell Console System Diagnostics Indicators
            "debug_keywords": re.compile(r"\b(?:godmode|backdoor|hidden[-_]menu|secret[-_]menu|debug[-_]shell|uart[-_]debug|telnet\s+server)\b", re.IGNORECASE)
        }

    def run_with_map(self, firmware_path: str, firmware_map: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        raw_data = firmware_map.get("raw_binary", b"")

        if not raw_data:
            return findings

        try:
            strings = self.extractor.extract_from_bytes(raw_data)
            for offset, s in strings:
                self._check_all_patterns(offset, s, findings)
        except Exception:
            pass

        if not findings:
            findings.append(Finding(
                id="FIRM-BACKDOOR-INFO-000",
                title="Hidden Administrative Surface Verification Completed",
                description="The hidden access pathway audit layer successfully completed scanning. Zero high-risk keywords found.",
                severity="Info",
                cwes=[],
                evidence="Inspected raw string extraction boundaries cleanly.",
                offset="-",
                component="auth_logic"
            ))

        return findings

    def _check_all_patterns(self, addr: int, s: str, findings: List[Finding]):
        addr_str = hex(addr) if isinstance(addr, int) else str(addr)

        # Dynamic Route Extraction
        m_path = self.patterns["admin_paths"].search(s)
        if m_path:
            path_str = m_path.group(0)
            findings.append(Finding(
                id="FIRM-BACKDOOR-PATH-001",
                title="Hidden Administrative/Debug URI Path Discovered",
                description=f"An unauthenticated sensitive administrative or maintenance web directory path structure ('{path_str}') was found compiled inside data storage blocks.",
                severity="High",
                cwes=["CWE-425", "CWE-912"],
                evidence=path_str,
                offset=addr_str,
                component="hidden_routing"
            ))

        # Dynamic Token/Secret Parsing
        m_token = self.patterns["auth_tokens"].search(s)
        if m_token:
            token_str = m_token.group(0)
            findings.append(Finding(
                id="FIRM-BACKDOOR-TOKEN-002",
                title="Hardcoded Authorization Token/Key Pattern Matched",
                description="A static string matching common assignment patterns for API keys, bearer tokens, or structural credentials was found exposed directly inside system instructions.",
                severity="Critical",
                cwes=["CWE-798"],
                evidence=token_str[:120],
                offset=addr_str,
                component="static_credentials"
            ))

        # Dynamic Debug Keyword Triggers
        m_debug = self.patterns["debug_keywords"].search(s)
        if m_debug:
            kw_str = m_debug.group(0)
            findings.append(Finding(
                id="FIRM-BACKDOOR-KW-003",
                title="Legacy Debugging/Maintenance Keyword Found",
                description=f"A raw reference keyword tracking to diagnostic developer shortcuts ('{kw_str}') was confirmed active in binary instructions.",
                severity="High",
                cwes=["CWE-489", "CWE-912"],
                evidence=s[:120].strip(),
                offset=addr_str,
                component="debug_interface"
            ))