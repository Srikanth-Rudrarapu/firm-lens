import struct
from typing import List, Dict, Any
from firm_lens.utils.findings import Finding

class ESP32PartitionAnalyzer:
    """
    Advanced Partition Table Security Analyzer.
    Scans full memory structures to reassemble ESP-IDF partition layouts,
    running deep audits on storage overlaps, encryption flags, and upgrade safety.
    Operates as a stateless sensor decoupled from core rules and threat intelligence.
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

        if not partitions:
            return findings

        labels = {str(p.get("name", "")).strip().lower() for p in partitions}
        
        # Check 1: Missing Basic NVS Space
        if "nvs" not in labels:
            findings.append(Finding(
                id="FIRM-ESP32-PART-010",
                evidence="NVS allocation block missing from device structural maps."
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
                        factory_partition_name = p_name 
                    elif 0x10 <= p_subtype < 0x20:
                        has_ota_slots = True

                # Check 2: Oversized NVS Boundaries
                if p_name == "nvs" and p_size > 0x10000:
                    findings.append(Finding(
                        id="FIRM-ESP32-PART-021",
                        evidence=f"Allocation size: {hex(p_size)} bytes at flash target base address {hex(p_offset_int)}",
                        offset=hex(p_offset_int)
                    ))

                # Check 3: Missing Encryption Enforced Flag on Sensitive Segments
                sensitive_keywords = ["nvs", "cert", "key", "auth", "credential", "secret"]
                if any(k in p_name for k in sensitive_keywords):
                    if (p_flags & 0x01) == 0:
                        findings.append(Finding(
                            id="FIRM-ESP32-PART-030",
                            evidence=f"Target Partition '{p_name}': Flags set to {hex(p_flags)} (Bit 0 Flash Encryption flag missing)",
                            offset=hex(p_offset_int)
                        ))

            except Exception:
                continue

        # Check 4: Boundary Overlap Integrity Scan
        partition_bounds.sort(key=lambda x: x[1])
        for i in range(len(partition_bounds) - 1):
            curr_name, curr_off, curr_size = partition_bounds[i]
            next_name, next_off, _ = partition_bounds[i+1]
            
            if curr_off + curr_size > next_off:
                findings.append(Finding(
                    id="FIRM-ESP32-PART-040",
                    evidence=f"'{curr_name}' tail address ({hex(curr_off + curr_size)}) bleeds into '{next_name}' start block ({hex(next_off)})",
                    offset=hex(curr_off)
                ))

        # Check 5: Insecure Upgrade Architecture Audits
        if has_ota_slots and not has_ota_data:
            findings.append(Finding(
                id="FIRM-ESP32-PART-050",
                evidence="OTA application bins exist without companion otadata reference partition types."
            ))
        elif has_factory and not has_ota_slots:
            findings.append(Finding(
                id="FIRM-ESP32-PART-055",
                evidence=f"Architecture maps a single '{factory_partition_name}' application slot without secondary OTA recovery partitions."
            ))

        return findings

    def _deep_carve_flash_space(self, data: bytes) -> List[Dict[str, Any]]:
        """Signature-assisted structural flash layout carver."""
        for offset in range(0, len(data) - 32, 32):
            chunk = data[offset : offset + 32]
            if len(chunk) < 32:
                continue
                
            try:
                magic_res, p_type, p_subtype, p_offset, p_size, label_raw, flags = struct.unpack(self.part_fmt, chunk)
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
                                "offset": hex(off),
                                "size": sz,
                                "flags": flgs
                            })
                        elif m_res == 0xEFEB:
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
        return []
