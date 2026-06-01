import re
from typing import List, Dict, Any
from firm_lens.utils.string_extractor import StringExtractor
from firm_lens.utils.findings import Finding

class InsecureEndpointAnalyzer:
    """
    Advanced Network Surface & Infrastructure Topology Mapper.
    Extracts raw transport endpoints, cloud boundaries, and network protocols.
    """

    def __init__(self, min_string_length: int = 4):
        self.extractor = StringExtractor(min_length=min_string_length)
        
        # Industrial-grade broad-spectrum regular expression matrix
        self.patterns = {
            # Catch raw URLs anywhere in text fields
            "url_clear": re.compile(r"\b(http|mqtt|ws)://[a-zA-Z0-9._:/\-?&=%]+"),
            "url_secure": re.compile(r"\b(https|mqtts|wss)://[a-zA-Z0-9._:/\-?&=%]+"),
            
            # Broad-spectrum IPv4 Carving (Validates standard dotted decimal blocks)
            "ipv4_raw": re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
            
            # Infrastructure TLD Mapping (Catches naked domain hostnames lacking prefixes)
            "naked_host": re.compile(r"\b[a-zA-Z0-9_\-]+\.(?:com|net|org|io|local|edu|gov|xyz)\b"),
            
            # Cloud Ecosystem Indicators
            "aws_iot": re.compile(r"(?i)[a-z0-9\-]+\.iot\.[a-z0-9\-]+\.amazonaws\.com"),
            "azure_iot": re.compile(r"(?i)[a-zA-Z0-9\-]+\.azure-devices\.net"),
            "gcp_iot": re.compile(r"(?i)mqtt\.googleapis\.com"),
        }

    def run_with_map(self, firmware_path: str, firmware_map: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        raw_data = firmware_map.get("raw_binary", b"")

        if not raw_data:
            return findings

        try:
            strings = self.extractor.extract_from_bytes(raw_data)
            for offset, s in strings:
                self._match_patterns(offset, s, findings)
        except Exception:
            pass

        # Empty severity findings are filtered out.

        return findings

    def _match_patterns(self, addr: int, s: str, findings: List[Finding]):
        addr_str = hex(addr) if isinstance(addr, int) else str(addr)

        # 1. Cleartext URL Detections
        m_clear = self.patterns["url_clear"].search(s)
        if m_clear:
            url = m_clear.group(0)
            findings.append(Finding(
                id="FIRM-ENDPOINT-CLEAR-001",
                title="Cleartext Network Transport Endpoint Discovered",
                description=f"A hardcoded cleartext network destination string ({url}) was extracted. This exposes the device payload traffic to MitM manipulation.",
                severity="High",
                cwes=["CWE-319"],
                evidence=url[:120],
                offset=addr_str,
                component="network_stack"
            ))

        # 2. Secure URL Detections (For Infrastructure Mapping)
        m_secure = self.patterns["url_secure"].search(s)
        if m_secure:
            url = m_secure.group(0)
            findings.append(Finding(
                id="FIRM-ENDPOINT-SECURE-002",
                title="Hardcoded Encrypted Network Endpoint Target",
                description=f"An encrypted structural network destination path ({url}) was mapped inside code memory boundaries.",
                severity="Medium",
                cwes=["CWE-200"],
                evidence=url[:120],
                offset=addr_str,
                component="network_stack"
            ))

        # 3. Broad-Spectrum IPv4 Detections
        m_ip = self.patterns["ipv4_raw"].search(s)
        if m_ip:
            ip_str = m_ip.group(0)
            # Filter out obvious false positives like version numbers or subnet masks
            if not ip_str.startswith(("255.", "0.")) and not ip_str.endswith(".255"):
                findings.append(Finding(
                    id="FIRM-ENDPOINT-IP-001",
                    title="Static IPv4 Address Infiltration Boundary",
                    description=f"A hardcoded static IPv4 target address identifier string ('{ip_str}') was located directly inside system binary instructions.",
                    severity="High" if not ip_str.startswith(("192.168.", "10.", "172.")) else "Medium",
                    cwes=["CWE-798", "CWE-200"],
                    evidence=ip_str,
                    offset=addr_str,
                    component="static_routes"
                ))

        # 4. Naked Host Domain Identification
        m_host = self.patterns["naked_host"].search(s)
        if m_host:
            host_str = m_host.group(0)
            # Make sure it isn't just catching code symbols or standard filenames
            if not host_str.startswith(("struct.", "class.", "void.")):
                findings.append(Finding(
                    id="FIRM-ENDPOINT-HOST-003",
                    title="Naked Operational Hostname Destination Extracted",
                    description=f"A hardcoded operational hostname asset domain context string ('{host_str}') was uncovered outside of URL wrapper wrappers.",
                    severity="Medium",
                    cwes=["CWE-200"],
                    evidence=host_str,
                    offset=addr_str,
                    component="dns_resolver"
                ))

        # 5. Cloud Ecosystem Integrations Verification
        for cloud in ["aws_iot", "azure_iot", "gcp_iot"]:
            m_cloud = self.patterns[cloud].search(s)
            if m_cloud:
                findings.append(Finding(
                    id="FIRM-ENDPOINT-CLOUD-001",
                    title=f"Enterprise Cloud Host Ecosystem Identified: {cloud.replace('_', ' ').upper()}",
                    description="Identification of backend cloud cloud hosting infrastructure simplifies endpoint enumeration vectors for external audits.",
                    severity="Medium",
                    cwes=["CWE-200"],
                    evidence=m_cloud.group(0)[:120],
                    offset=addr_str,
                    component="cloud_gateways"
                ))