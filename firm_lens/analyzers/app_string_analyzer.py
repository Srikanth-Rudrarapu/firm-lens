import re
from typing import List, Dict, Any
from firm_lens.utils.string_extractor import StringExtractor
from firm_lens.utils.findings import Finding

class AppStringAnalyzer:
    """Detects application-layer information leakage, hardcoded credentials, and struct-based memory escrow."""
    def __init__(self):
        self.extractor = StringExtractor(min_length=4)
        
        # Heuristic 1: Explicit Key-Value assignments (e.g., JSON, INI, or explicit string logs)
        self.secret_rx_bytes = re.compile(b"(?i)(?:\"|'|)(password|passwd|secret|ssid|api[_-]?key)(?:\"|'|)[\\x00-\\x20:=,]+(?:\"|'|)([\\x20-\\x7E]{4,64})(?:\"|'|)")
        self.pk_rx_bytes = re.compile(b"(?i)(BEGIN[\\x20-\\x7E]*PRIVATE KEY)")
        
        # Heuristic 2: ESP-IDF wifi_config_t Memory Layout Signature
        # Looks for 1-31 printable chars + null padding, immediately followed by 8-63 printable chars + null padding
        self.struct_rx_bytes = re.compile(b"([\\x20-\\x7E]{3,31})\\x00+([\\x20-\\x7E]{8,63})\\x00+")

        self.internal_vars = {"identifier", "ap.passwd", "sta.authmode", "sta.lis_intval", "wifi_config"}

    def run_with_map(self, firmware_path: str, firmware_map: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        raw_data = firmware_map.get("raw_binary", b"")
        if not raw_data: 
            return findings

        # --- THE O-1 HEURISTIC NOISE FILTERS ---
        c_format_junk = ["%s", "%d", "%x", "%02x", "%.*s", "%lu", "%c", "%u", "%04x"]
        log_junk = ["fail", "error", "esp_err", "length", "encrypted", "threshold", "position", "bssid", "same", "none", "hidden", "making it impossible", "convert fail"]

        try:
            # 1. Scan for ESP-IDF wifi_config_t Structs in raw memory
            for match in self.struct_rx_bytes.finditer(raw_data):
                potential_ssid = match.group(1).decode('ascii', errors='ignore').strip()
                potential_pass = match.group(2).decode('ascii', errors='ignore').strip()
                
                # Filter out format strings and logs from the struct scanner
                if any(junk in potential_ssid.lower() or junk in potential_pass.lower() for junk in c_format_junk + log_junk):
                    continue
                    
                # If it looks like a valid credential pair in memory, flag it
                if len(potential_pass) >= 8 and " " not in potential_pass:
                    findings.append(Finding(
                        id="FL-CRED-STRUCT", 
                        title="Hardcoded Wi-Fi Config Struct Detected",
                        evidence=f"Memory Block -> SSID: '{potential_ssid}' | PSK: '{potential_pass}'", 
                        offset=hex(match.start())
                    ))

            # 2. Scan for Explicit Strings
            for match in self.secret_rx_bytes.finditer(raw_data):
                key = match.group(1).decode('ascii', errors='ignore').upper()
                secret_val = match.group(2).decode('ascii', errors='ignore')
                
                clean_secret = re.sub(r'[^\x20-\x7E]', '', secret_val).strip()
                clean_lower = clean_secret.lower()
                
                if len(clean_secret) < 4 or clean_lower in self.internal_vars:
                    continue
                if any(junk in clean_lower for junk in c_format_junk):
                    continue
                if any(junk in clean_lower for junk in log_junk):
                    continue

                findings.append(Finding(
                    id="FL-CRED-HARDCODED", 
                    title=f"Hardcoded {key} String Escrow",
                    evidence=f"{key}={clean_secret}", 
                    offset=hex(match.start())
                ))

            # 3. Scan for Private Keys
            for match in self.pk_rx_bytes.finditer(raw_data):
                pk_val = match.group(1).decode('ascii', errors='ignore')
                clean_pk = re.sub(r'[^\x20-\x7E]', '', pk_val).strip()
                findings.append(Finding(
                    id="FL-CRED-PRIVATEKEY", 
                    title="Private Key Header Detected",
                    evidence=clean_pk, 
                    offset=hex(match.start())
                ))
        except Exception:
            pass
        return findings

    def run(self, firmware_path: str) -> List[Finding]: 
        return []