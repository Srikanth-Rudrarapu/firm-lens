import re
from typing import List, Dict, Any

from firm_lens.utils.string_extractor import StringExtractor
from firm_lens.utils.findings import Finding
from firm_lens.utils.cwe_mapping import CWE_MAP

class InsecureEndpointAnalyzer:
    """
    Advanced Network Surface Mapper.
    Identifies insecure cleartext channels and maps sensitive cloud infrastructure
    within the application's memory segments.
    """

    def __init__(self, min_string_length: int = 4):
        self.extractor = StringExtractor(min_length=min_string_length)

        # High-precision regex patterns for modern IoT infrastructure
        self.patterns = {
            "http": re.compile(r"http://[a-zA-Z0-9._:/\-?&=%]+"),
            "https": re.compile(r"https://[a-zA-Z0-9._:/\-?&=%]+"),
            "mqtt": re.compile(r"mqtt://[a-zA-Z0-9._:/\-]+"),
            "mqtts": re.compile(r"mqtts://[a-zA-Z0-9._:/\-]+"),
            "ws": re.compile(r"ws://[a-zA-Z0-9._:/\-]+"),
            "wss": re.compile(r"wss://[a-zA-Z0-9._:/\-]+"),
            "ip": re.compile(r"\b(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"),
            "aws_iot": re.compile(r"[a-z0-9\-]+\.iot\.[a-z0-9\-]+\.amazonaws\.com"),
            "azure_iot": re.compile(r"[a-zA-Z0-9\-]+\.azure-devices\.net"),
            "gcp_iot": re.compile(r"mqtt\.googleapis\.com"),
        }

    def run(self, firmware_map: Dict[str, Any]) -> List[Finding]:
        """
        Processes segments to identify network-based vulnerabilities.
        """
        findings: List[Finding] = []
        
        # Iterate through segments (Bootloader, App, etc.)
        for segment in firmware_map.get("segments", []):
            segment_data = segment.get("data", b"")
            load_addr = segment.get("addr", "0x0")
            
            # Use memory-efficient string extraction
            strings = self.extractor.extract_from_bytes(segment_data)

            for offset, s in strings:
                # Calculate Virtual Memory Address
                relative_addr = int(load_addr, 16) + offset
                self._match_patterns(relative_addr, s, findings)

        return findings

    def _match_patterns(self, addr: int, s: str, findings: List[Finding]):
        """Internal logic to categorize endpoints by severity."""
        
        # 1. Cleartext Communication (High/Critical)
        for proto in ["http", "mqtt", "ws"]:
            m = self.patterns[proto].search(s)
            if m:
                url = m.group(0)
                findings.append(Finding(
                    id=f"FIRM-ENDPOINT-{proto.upper()}-001",
                    title=f"Insecure {proto.upper()} endpoint detected",
                    description=f"A cleartext {proto.upper()} channel was found. This protocol lacks encryption and is vulnerable to Man-in-the-Middle (MITM) attacks.",
                    severity="High",
                    cwes=[CWE_MAP.get("insecure_http", "CWE-319")],
                    evidence=url,
                    offset=hex(addr),
                    component="network_stack"
                ))

        # 2. Cloud IoT Infrastructure (Medium - Data Leakage Risk)
        for cloud in ["aws_iot", "azure_iot", "gcp_iot"]:
            m = self.patterns[cloud].search(s)
            if m:
                findings.append(Finding(
                    id="FIRM-ENDPOINT-CLOUD-001",
                    title=f"Hardcoded Cloud IoT Endpoint: {cloud.replace('_', ' ').upper()}",
                    description="Identification of backend cloud infrastructure allows attackers to map the device ecosystem and target the provider API.",
                    severity="Medium",
                    cwes=["CWE-200"],
                    evidence=m.group(0),
                    offset=hex(addr),
                    component="cloud_config"
                ))

        # 3. Internal IPs (Low - Reconnaissance Risk)
        m = self.patterns["ip"].search(s)
        if m:
            findings.append(Finding(
                id="FIRM-ENDPOINT-IP-001",
                title="Internal IP Address Exposure",
                description="Hardcoded internal IPs can reveal local network architecture or management interfaces.",
                severity="Low",
                cwes=["CWE-200"],
                evidence=m.group(0),
                offset=hex(addr),
                component="debug_config"
            ))