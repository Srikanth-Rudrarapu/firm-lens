import re
from typing import List, Dict, Any
from firm_lens.utils.string_extractor import StringExtractor
from firm_lens.utils.findings import Finding

class InsecureEndpointAnalyzer:
    """Infrastructure Interface and Network Surface Mapping Sensor."""

    def __init__(self):
        self.extractor = StringExtractor(min_length=4)
        self.ip_rx = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
        # Capture full URLs, avoiding C format specifiers
        self.uri_rx = re.compile(r"\b(https?|mqtts?|wss?|coaps?):\/\/[a-zA-Z0-9\-\.]+(?:\/[a-zA-Z0-9\-\._~:/\?#\[\]@!$&'\(\)\*\+,;=]*)?")

    def run_with_map(self, firmware_path: str, firmware_map: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        raw_data = firmware_map.get("raw_binary", b"")

        if not raw_data:
            return findings

        c_format_junk = ["%s", "%d", "%02x", "%x"]

        try:
            strings = self.extractor.extract_from_bytes(raw_data)
            for offset, found_str in strings:
                cleaned = found_str.strip()
                
                # Filter out format strings
                if any(junk in cleaned.lower() for junk in c_format_junk):
                    continue

                if self.ip_rx.search(cleaned):
                    for ip in self.ip_rx.findall(cleaned):
                        # Filter out common localhost/broadcast noise if desired, or keep to map surface
                        findings.append(Finding(
                            id="FL-NETW-IP", 
                            title="Static IPv4 Boundary", 
                            evidence=f"Target IPv4 Address: {ip}", 
                            offset=hex(offset)
                        ))
                        
                elif self.uri_rx.search(cleaned):
                    rule_id = "FL-NETW-CLEARTEXT" if any(p in cleaned for p in ["http://", "mqtt://", "ws://"]) else "FL-NETW-URL"
                    title = "Cleartext Transport Endpoint" if rule_id == "FL-NETW-CLEARTEXT" else "Network Endpoint Target"
                    findings.append(Finding(
                        id=rule_id, 
                        title=title, 
                        evidence=f"Payload path: '{cleaned}'", 
                        offset=hex(offset)
                    ))
        except Exception:
            pass

        return findings

    def run(self, firmware_path: str) -> List[Finding]:
        return []