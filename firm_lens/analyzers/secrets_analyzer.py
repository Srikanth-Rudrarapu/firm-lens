import re
from typing import List, Dict, Any
from firm_lens.utils.string_extractor import StringExtractor
from firm_lens.utils.findings import Finding

class SecretsAnalyzer:
    """Identifies static key material using null-terminated binary memory slicing."""
    def __init__(self):
        self.extractor = StringExtractor(min_length=6)
        
        # Core markers used by mbedTLS and standard crypto libraries
        self.pem_markers = [
            b"BEGIN RSA PRIVATE KEY", b"BEGIN EC PRIVATE KEY",
            b"BEGIN PRIVATE KEY", b"BEGIN ENCRYPTED PRIVATE KEY"
        ]
        
        # Targeted context assignments (e.g. password="Admin@123!")
        self.context_pattern = re.compile(r'(?i)(?:password|passwd|pwd|secret|token|api_key)[\s:=]+([!-~]{6,})')
        
        # Wi-Fi noise reduction regexes imported from app_string_analyzer
        self.wifi_noise_regex = re.compile(
            r'(?i)(?:%[sdpux08]|/IDF/|/components/|/lwip/|\.c$|\.h$|\.cpp$|esp_|\+BLE|\+CIP|TLS-|AES-|LWIP_|ESP32|^[0-9]+$|scan\s|debug|default|unknown|null|empty|Server closed)'
        )
        self.wifi_c_syntax = re.compile(r'(->|==|<=|>=|!=|<|>|\(\)|\.c$|\.h$|\.cpp$)')
        self.wifi_date_time = re.compile(r'(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{4}')
        self.wifi_version = re.compile(r'^v?\d+\.\d+(\.\d+)?(-\w+)?$')
        self.wifi_oid_noise = re.compile(r'(?i)(^id-at-|^id-kp-|dnQualifier|Authentication|Org Unit)')
        self.wifi_sys_internals = re.compile(r'(?i)(tcp_|udp_|memp_|netif_|prv[A-Z]|xTask|vTask|HPE_|oversize|strict mode|xQueue|vRingbuffer|Semaphore|Mutex|app_main)')

    def run_with_map(self, firmware_path: str, firmware_map: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        raw_data = firmware_map.get("raw_binary", b"")
        if not raw_data: 
            return findings

        # 1. Null-Terminated Memory Block Extraction for Full Private Keys
        for marker in self.pem_markers:
            offset = 0
            while True:
                offset = raw_data.find(marker, offset)
                if offset == -1: 
                    break
                
                    # ---- TEST KEY EXCLUSION ----
                    if re.search(r'(?i)(test|example|sample|dummy)', full_key):
                        offset += len(marker)
                        continue

                    # Reject keys shorter than 200 chars (fragments, not real keys)
                    if len(full_key) < 200:
                        offset += len(marker)
                        continue

                    findings.append(Finding(
                        id="FL-CRED-PRIVATEKEY",
                        title="Cryptographic Private Key Extracted",
                        evidence=full_key,
                        offset=hex(offset)
                    ))

                offset += len(marker)

        # 2. Targeted Hardcoded Secrets & Wi-Fi Struct Analysis
        try:
            strings = self.extractor.extract_from_bytes(raw_data)
            for offset, found_str in strings:
                # --- A. General Hardcoded Secrets ---
                clean_str = re.sub(r'[^\x20-\x7E]', '', found_str).strip()
                ctx_match = self.context_pattern.search(clean_str)
                if ctx_match:
                    secret_val = ctx_match.group(1)
                    noise_pattern = re.compile(r'(?i)(%[sdpuxn]|/idf/|/components/|\.c$|\.h$|\.cpp$|esp_|debug|scan\s|less\s|test|example|dummy|placeholder|changeme|Server closed)')
                    
                    if not noise_pattern.search(secret_val) and not secret_val.isdigit():
                        has_upper = bool(re.search(r'[A-Z]', secret_val))
                        has_lower = bool(re.search(r'[a-z]', secret_val))
                        has_digit = bool(re.search(r'\d', secret_val))
                        has_special = bool(re.search(r'[^a-zA-Z0-9]', secret_val))
                        has_letter = has_upper or has_lower
                        
                        passes = (
                            (has_upper and has_lower and has_digit)
                            or (has_letter and has_digit and has_special)
                            or (len(secret_val) >= 20)
                        )
                        if passes:
                            findings.append(Finding(
                                id="FL-CRED-HARDCODED",
                                title="Hardcoded Credential or Token",
                                cwes=["CWE-798"],
                                evidence=f"[{hex(offset)}] Value: {secret_val} (Context: {clean_str})",
                                offset=hex(offset)
                            ))

                # --- B. Wi-Fi Config Struct (Merged from app_string_analyzer) ---
                raw_ssid_len = len(found_str)
                if 3 <= raw_ssid_len <= 32:
                    clean_ssid = found_str.strip()
                    if not self.wifi_noise_regex.search(clean_ssid) and not self.wifi_c_syntax.search(clean_ssid):
                        padding_length = 32 - raw_ssid_len
                        is_padded = True
                        if padding_length > 0:
                            padding_bytes = raw_data[offset + raw_ssid_len : offset + 32]
                            if padding_bytes != (b'\x00' * padding_length):
                                is_padded = False
                        
                        if is_padded:
                            psk_offset = offset + 32
                            if psk_offset + 64 <= len(raw_data):
                                psk_block = raw_data[psk_offset:psk_offset+64]
                                null_idx = psk_block.find(b'\x00')
                                
                                if 8 <= null_idx <= 63:
                                    psk_candidate = psk_block[:null_idx].decode('ascii', errors='replace').strip()
                                    
                                    if re.match(r'^[\x20-\x7E]+$', psk_candidate):
                                        if not (self.wifi_noise_regex.search(psk_candidate) or 
                                                self.wifi_c_syntax.search(psk_candidate) or
                                                clean_ssid.count('_') > 2 or psk_candidate.count('_') > 2 or
                                                clean_ssid.count(' ') > 3 or psk_candidate.count(' ') > 3 or
                                                clean_ssid.startswith('-') or clean_ssid.count('-') > 4 or
                                                self.wifi_date_time.search(clean_ssid) or self.wifi_date_time.search(psk_candidate) or
                                                self.wifi_version.match(clean_ssid) or self.wifi_version.match(psk_candidate) or
                                                re.match(r'^\d{2}:\d{2}:\d{2}$', psk_candidate) or re.match(r'^\d{2}:\d{2}:\d{2}$', clean_ssid) or
                                                self.wifi_oid_noise.search(clean_ssid) or self.wifi_oid_noise.search(psk_candidate) or
                                                self.wifi_sys_internals.search(clean_ssid) or self.wifi_sys_internals.search(psk_candidate)): 
                                            
                                            findings.append(Finding(
                                                id="FL-CRED-STRUCT",
                                                title="Hardcoded Wi-Fi Config Struct Detected",
                                                severity="Critical",
                                                cwes=["CWE-798", "CWE-259"], 
                                                evidence=f"[{hex(offset)}] Memory Block -> SSID: '{clean_ssid}' | PSK: '{psk_candidate}'",
                                                offset=hex(offset)
                                            ))
        except Exception:
            pass
            
        return findings

    def run(self, firmware_path: str) -> List[Finding]: 
        return []