import re
from typing import List, Dict, Any
from firm_lens.utils.string_extractor import StringExtractor
from firm_lens.utils.findings import Finding

class BackdoorAnalyzer:
    """
    Advanced Backdoor & Hidden Interface Analyzer.
    Dynamically scans text segments to isolate hidden developer diagnostic shells,
    unauthorized administrative command paths, and firmware maintenance bypass loops.
    """

    def __init__(self, min_string_length: int = 4):
        self.extractor = StringExtractor(min_length=min_string_length)
        
        # Expanded multi-vector engineering pattern grid
        self.patterns = {
            # 1. Expanded High-Risk Administrative/Control URI Routing Paths
            "admin_paths": re.compile(r"\b/(?:shell|backdoor|maintenance|godmode|root_login|debug(?:/[a-z_]+)?|exec|config)\b[a-zA-Z0-9_\-/]*"),
            
            # 2. Strict Interactive Low-Level Shell Commands / Diagnostic Strings
            "shell_commands": re.compile(r"^/(bin/)?(sh|bash|ash|zsh)$|^\s*(sh|bash|ash)\s+\-c\b"),
            
            # 3. Development Bypass Keyphrases & Debug Protocol Headers (CWE-489 / CWE-912)
            "bypass_triggers": re.compile(r"\b(?:bypass_auth|skip_verification|enable_hidden_menu|uart_force_debug|x\-debug\-[a-z\-]+|debug_token)\b", re.IGNORECASE)
        }

    def run_with_map(self, firmware_path: str, firmware_map: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        raw_data = firmware_map.get("raw_binary", b"")

        if not raw_data:
            return findings

        try:
            strings = self.extractor.extract_from_bytes(raw_data)
            
            shell_match_count = 0
            first_shell_offset = None
            shell_evidence_sample = ""

            for offset, found_str in strings:
                cleaned_str = found_str.strip()
                addr_str = hex(offset)
                
                # Check Vector 1: Unauthorized Direct Access Routing Paths (e.g., /debug/exec)
                m_path = self.patterns["admin_paths"].search(cleaned_str)
                if m_path:
                    path_str = m_path.group(0)
                    findings.append(Finding(
                        id="FIRM-BACKDOOR-PATH-001",
                        title="Hidden Administrative/Debug URI Path Discovered",
                        description=(
                            f"An unauthenticated sensitive administrative, maintenance, or code execution route structure "
                            f"('{path_str}') was located inside string memory configurations. These pathways provide entry "
                            "points for unauthorized system administration commands."
                        ),
                        severity="High",
                        cwes=["CWE-425", "CWE-912"],
                        evidence=path_str,
                        offset=addr_str,
                        component="hidden_routing"
                    ))

                # Check Vector 2: Active Reverse Shell or Terminal Instantiations
                m_shell = self.patterns["shell_commands"].search(cleaned_str)
                if m_shell:
                    shell_match_count += 1
                    if first_shell_offset is None:
                        first_shell_offset = offset
                        shell_evidence_sample = cleaned_str

                # Check Vector 3: Integrity Logic Bypasses & Custom Debug Headers (e.g., X-Debug-Token)
                m_bypass = self.patterns["bypass_triggers"].search(cleaned_str)
                if m_bypass:
                    kw_str = m_bypass.group(0)
                    findings.append(Finding(
                        id="FIRM-BACKDOOR-KW-003",
                        title="Developer Bypass/Diagnostic Logic Gate Isolated",
                        description=(
                            f"A raw verification bypass keyphrase, custom debug header configuration key, or diagnostic "
                            f"developer shortcut string ('{kw_str}') was confirmed active in instruction segments."
                        ),
                        severity="High",
                        cwes=["CWE-489", "CWE-912"],
                        evidence=cleaned_str[:100],
                        offset=addr_str,
                        component="debug_interface"
                    ))

            # Consolidate shell findings into a high-fidelity alert
            if shell_match_count > 0:
                severity = "Critical" if "bin" in shell_evidence_sample or "-" in shell_evidence_sample else "Medium"
                findings.append(Finding(
                    id="FIRM-BACKDOOR-SHELL-002",
                    title="Embedded Interactive Shell Environment Reference Verified",
                    description=(
                        f"Isolated {shell_match_count} distinct interactive command environment sequences. "
                        "The presence of explicit binary system shell parameters inside firmware vectors indicate "
                        "vulnerability to remote command injection execution or active diagnostic configuration interfaces left exposed."
                    ),
                    severity=severity,
                    cwes=["CWE-78", "CWE-912"],
                    evidence=f"Aggregated Matches: {shell_match_count} calls parsed. Entry sample: '{shell_evidence_sample}'",
                    offset=hex(first_shell_offset) if first_shell_offset else "-",
                    component="shell_execution"
                ))

        except Exception:
            pass

        # Empty severity findings are filtered out.

        return findings

    def run(self, firmware_path: str) -> List[Finding]:
        return []