import re
from typing import List, Dict, Any

from firm_lens.utils.string_extractor import StringExtractor
from firm_lens.utils.findings import Finding
from firm_lens.utils.cwe_mapping import CWE_MAP

class BackdoorAnalyzer:
    """
    Advanced Backdoor & Hidden Interface Analyzer.
    
    Identifies undocumented access paths, hidden debug shells, and 
    maintenance triggers by analyzing application memory segments.
    """

    def __init__(self, min_string_length: int = 4):
        self.extractor = StringExtractor(min_length=min_string_length)

        # High-risk patterns tailored for firmware and bootloader strings
        self.patterns = {
            "backdoor_keywords": [
                re.compile(r"(?i)\bbackdoor\b"),
                re.compile(r"(?i)\bgodmode\b"),
                re.compile(r"(?i)\bhidden menu\b"),
                re.compile(r"(?i)\bsecret menu\b"),
                re.compile(r"(?i)\bdebug shell\b"),
                re.compile(r"(?i)\bmaintenance mode\b"),
            ],
            "credentials": [
                re.compile(r"(?i)\b(root|admin|superuser)\s+password\b"),
                re.compile(r"(?i)\bdefault password\b"),
                re.compile(r"(?i)\bdebug password\b"),
            ],
            "commands": [
                re.compile(r"(?i)\bdebug_cmd_[a-z0-9_]+\b"),
                re.compile(r"(?i)\bhidden_cmd_[a-z0-9_]+\b"),
            ],
            "telnet_serial": [
                re.compile(r"(?i)telnet server started"),
                re.compile(r"(?i)press any key to stop autoboot"),
                re.compile(r"(?i)uart debug"),
            ],
        }

    def run(self, firmware_map: Dict[str, Any]) -> List[Finding]:
        """
        Processes segments to identify potential hidden access paths.
        """
        findings: List[Finding] = []
        
        for segment in firmware_map.get("segments", []):
            segment_data = segment.get("data", b"")
            load_addr = segment.get("addr", "0x0")
            
            # Static Analysis: Isolate strings within this specific memory block
            strings = self.extractor.extract_from_bytes(segment_data)

            for offset, s in strings:
                # Calculate the precise memory location for the report
                relative_addr = int(load_addr, 16) + offset
                
                self._check_backdoor_keywords(relative_addr, s, findings)
                self._check_credentials(relative_addr, s, findings)
                self._check_commands(relative_addr, s, findings)
                self._check_telnet_serial(relative_addr, s, findings)

        return findings

    def _check_backdoor_keywords(self, addr: int, s: str, findings: List[Finding]):
        for rx in self.patterns["backdoor_keywords"]:
            if rx.search(s):
                findings.append(Finding(
                    id="FIRM-BACKDOOR-001",
                    title="Potential Backdoor/Hidden Interface Indicator",
                    description="Strings suggesting undocumented access paths found. These often bypass standard authentication.",
                    severity="High",
                    cwes=[CWE_MAP.get("backdoor", "CWE-912")],
                    evidence=s[:120],
                    offset=hex(addr),
                    component="app_logic"
                ))
                break

    def _check_credentials(self, addr: int, s: str, findings: List[Finding]):
        for rx in self.patterns["credentials"]:
            if rx.search(s):
                findings.append(Finding(
                    id="FIRM-BACKDOOR-002",
                    title="Hardcoded Privileged Credential Reference",
                    description="Detected references to admin, root, or debug passwords in firmware strings.",
                    severity="High",
                    cwes=["CWE-798", "CWE-912"],
                    evidence=s[:120],
                    offset=hex(addr),
                    component="auth_logic"
                ))
                break

    def _check_commands(self, addr: int, s: str, findings: List[Finding]):
        for rx in self.patterns["commands"]:
            if rx.search(s):
                findings.append(Finding(
                    id="FIRM-BACKDOOR-003",
                    title="Hidden Debug Command Identified",
                    description="Command identifiers found that may expose privileged operations via a serial or network shell.",
                    severity="Medium",
                    cwes=["CWE-489"],
                    evidence=s[:120],
                    offset=hex(addr),
                    component="shell_engine"
                ))
                break

    def _check_telnet_serial(self, addr: int, s: str, findings: List[Finding]):
        for rx in self.patterns["telnet_serial"]:
            if rx.search(s):
                findings.append(Finding(
                    id="FIRM-BACKDOOR-004",
                    title="Exposed Debug Interface String",
                    description="Strings indicating active Telnet or UART debug interfaces were found in the binary.",
                    severity="High",
                    cwes=["CWE-912", "CWE-489"],
                    evidence=s[:120],
                    offset=hex(addr),
                    component="debug_interface"
                ))
                break