from typing import List, Dict, Any
from firm_lens.utils.findings import Finding

class BackdoorAnalyzer:
    """Unauthorized Access and Maintenance Routing Sensor."""
    def __init__(self):
        self.backdoor_paths = [b"/config", b"/admin", b"/shell", b"/root_debug"]

    def run_with_map(self, firmware_path: str, firmware_map: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        raw_data = firmware_map.get("raw_binary", b"")
        if not raw_data: return findings

        for path in self.backdoor_paths:
            offset = 0
            while True:
                offset = raw_data.find(path, offset)
                if offset == -1: break
                findings.append(Finding(
                    id="FL-BACKDOOR-PATH",
                    evidence=f"Undocumented endpoint reference string string: {path.decode('ascii', errors='ignore')}",
                    offset=hex(offset)
                ))
                offset += len(path)
        return findings

    def run(self, firmware_path: str) -> List[Finding]: return []

