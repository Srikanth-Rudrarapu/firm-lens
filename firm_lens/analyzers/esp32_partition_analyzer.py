import struct
from typing import List, Dict, Any
from firm_lens.utils.findings import Finding

class ESP32PartitionAnalyzer:
    """
    Advanced Partition Table Security Analyzer.
    Scans full memory structures to reassemble ESP-IDF partition layouts,
    running deep audits on storage overlaps, encryption flags, and upgrade safety.
    """

    def __init__(self):
        # ESP-IDF Standard Partition Record Structural Layout (32 bytes total)
        self.part_fmt = "<HBBII16sI"

    def run_with_map(self, firmware_path: str, firmware_map: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        partitions = firmware_map.get("partitions", [])
        raw_data = firmware_map.get("raw_binary", b"")

        # Fall back to structural Carver if explicit extract layout is empty
        if not partitions and raw_data:
            partitions = self._deep_carve_flash_space(raw_data)

       # Empty severity findings are filtered out.
            return findings

        labels = {str(p.get("name", "")).strip().lower() for p in partitions}
        
        # Check 1: Missing Basic NVS Space
        if "nvs" not in labels:
            findings.append(Finding(
                id="FIRM-ESP32-PART-010",
                title="Missing Standard NVS Area Mapping",
                description=f"Non-Volatile Storage (NVS) configurations are absent. Found blocks: {list(labels)}",
                severity="Medium",
                cwes=["CWE-665"],
                evidence="NVS allocation block missing from device structural maps.",
                offset="-",
                component="partition_table"
            ))

        # Re-usable structures for cross-partition analytics
        partition_bounds = []
        has_ota_slots = False
        has_ota_data = False
        has_factory = False

        for p in partitions:
            try:
                p_name = str(p.get("name", "")).strip().lower()
                p_size = int(p.get("size", 0))
                p_flags = int(p.get("flags", 0))
                p_type = int(p.get("type", 0))
                p_subtype = int(p.get("subtype", 0))
                
                raw_offset = p.get("offset", "0x0")
                p_offset_int = int(raw_offset, 16) if isinstance(raw_offset, str) and raw_offset.startswith("0x") else int(raw_offset)
                
                partition_bounds.append((p.get("name", "unknown"), p_offset_int, p_size))

                # Track update topology patterns
                if p_type == 0x00:  # App Partition
                    if p_subtype == 0x00:
                        has_factory = True
                    elif 0x10 <= p_subtype < 0x20:
                        has_ota_slots = True
                elif p_type == 0x01 and p_subtype == 0x00:  # Data / OTA Select
                    has_ota_data = True

                # Check 2: Oversized NVS Boundaries (Credential Exhaustion Surface)
                if p_name == "nvs" and p_size > 0x10000:
                    findings.append(Finding(
                        id="FIRM-ESP32-PART-021",
                        title="Oversized NVS Storage Boundary Region",
                        description=f"An oversized NVS configuration target space ({hex(p_size)} bytes) increases offline key brute-force extraction exposure vectors.",
                        severity="Medium",
                        cwes=["CWE-312"],
                        evidence=f"Allocation size: {hex(p_size)} bytes at flash target base address {hex(p_offset_int)}",
                        offset=hex(p_offset_int),
                        component="partition_table"
                    ))

                # Check 3: Missing Encryption Enforced Flag on Sensitive Segments (CWE-311)
                # ESP-IDF definition: Bit 0 of partition flags requires Flash Encryption (PART_FLAG_ENCRYPTED = 1<<0)
                sensitive_keywords = ["nvs", "cert", "key", "auth", "credential", "secret"]
                if any(k in p_name for k in sensitive_keywords):
                    if (p_flags & 0x01) == 0:
                        findings.append(Finding(
                            id="FIRM-ESP32-PART-030",
                            title=f"Unencrypted Sensitive Data Partition Found: '{p.get('name')}'",
                            description=f"The partition '{p.get('name')}' stores system credentials but lacks the hardware-enforced encryption attribute bit.",
                            severity="High",
                            cwes=["CWE-311", "CWE-312"],
                            evidence=f"Partition entry flags field: {hex(p_flags)} (Bit 0 for Flash Encryption is disabled)",
                            offset=hex(p_offset_int),
                            component="partition_table"
                        ))

            except Exception:
                continue

        # Check 4: Boundary Overlap Integrity Scan (CWE-119 / Tamper Detection)
        partition_bounds.sort(key=lambda x: x[1])  # Sort by offset order
        for i in range(len(partition_bounds) - 1):
            curr_name, curr_off, curr_size = partition_bounds[i]
            next_name, next_off, _ = partition_bounds[i+1]
            
            if curr_off + curr_size > next_off:
                findings.append(Finding(
                    id="FIRM-ESP32-PART-040",
                    title="Critical Partition Boundary Overlap Detected",
                    description=f"Partition '{curr_name}' overlaps into '{next_name}'. This indicates flash space tampering, misconfigured layout links, or high vulnerability to memory boundary overwrites.",
                    severity="Critical",
                    cwes=["CWE-119", "CWE-125"],
                    evidence=f"'{curr_name}' tail address ({hex(curr_off + curr_size)}) bleeds into '{next_name}' start block ({hex(next_off)})",
                    offset=hex(curr_off),
                    component="partition_table"
                ))

        # Check 5: Insecure Upgrade Architecture Audits (CWE-1310)
        if has_ota_slots and not has_ota_data:
            findings.append(Finding(
                id="FIRM-ESP32-PART-050",
                title="Broken OTA Topology Matrix",
                description="App contains functional OTA update slots (ota_0/ota_1) but missing an 'otadata' control block partition. Rollbacks and dynamic boot selection maps are exposed or malfunctioning.",
                severity="High",
                cwes=["CWE-1310"],
                evidence="OTA application bins exist without companion otadata reference partition types.",
                offset="-",
                component="partition_table"
            ))
        elif has_factory and not has_ota_slots:
            findings.append(Finding(
                id="FIRM-ESP32-PART-055",
                title="Missing Secure Remote Patching Capabilities",
                description="Firmware relies strictly on static factory execution parameters without remote Over-the-Air upgrades. Discovered security vulnerabilities cannot be patched without physical JTAG/UART access.",
                severity="Medium",
                cwes=["CWE-1310"],
                evidence="Factory app slot is configured exclusively; no backup OTA slots mapped.",
                offset="-",
                component="partition_table"
            ))

        return findings

    def _deep_carve_flash_space(self, data: bytes) -> List[Dict[str, Any]]:
        """
        Signature-assisted structural carver: Steps through binary on 32-byte alignments.
        Locates valid partition tables by matching the ESP-IDF partition magic (0x50AA)
        and harvesting contiguous valid definitions.
        """
        for offset in range(0, len(data) - 32, 32):
            chunk = data[offset : offset + 32]
            if len(chunk) < 32:
                continue
                
            try:
                magic_res, p_type, p_subtype, p_offset, p_size, label_raw, flags = struct.unpack(self.part_fmt, chunk)
                
                # Check for the explicit ESP-IDF partition record magic signature
                if magic_res == 0x50AA and p_type in (0x00, 0x01) and 0 < p_size < len(data) and 0 < p_offset < len(data):
                    table_entries = []
                    curr_offset = offset
                    
                    while curr_offset + 32 <= len(data):
                        row = data[curr_offset : curr_offset + 32]
                        if row == b"\xFF" * 32 or row == b"\x00" * 32:
                            break
                            
                        m_res, t, st, off, sz, lbl, flgs = struct.unpack(self.part_fmt, row)
                        if m_res == 0x50AA:
                            name = lbl.split(b"\x00")[0].decode("ascii", errors="ignore").strip()
                            table_entries.append({
                                "name": name if name else f"part_{hex(off)}",
                                "type": t,
                                "subtype": st,
                                "offset": hex(off), # FIXED: Record target block destination address
                                "size": sz,
                                "flags": flgs
                            })
                        elif m_res == 0xEFEB: # MD5 boundary block
                            break
                        else:
                            break
                        curr_offset += 32
                    
                    if table_entries:
                        return table_entries
            except Exception:
                continue
                
        return []

    def run(self, firmware_path: str) -> List[Finding]:
        """Fallback standalone executor."""
        try:
            from firm_lens.extractor.esp32_extractor import ESP32Extractor
            extractor = ESP32Extractor()
            firmware_map = extractor.extract(firmware_path)
            if firmware_map:
                return self.run_with_map(firmware_path, firmware_map)
        except Exception:
            pass
        return []