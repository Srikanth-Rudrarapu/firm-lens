import struct
import os

class ESP32Extractor:
    """
    Pure Extraction Layer: Transforms binary data into a structured Firmware Map.
    Handles physical layouts natively to present rich data frameworks to Analyzers.
    """
    
    def __init__(self):
        # ESP32 Official Image Header Struct format (8 bytes core):
        # magic (1B), segment_count (1B), spi_mode (1B), spi_speed_size (1B), entry_addr (4B)
        self.header_fmt = "<BBBB I"
        
        # magic/res (2B), type (1B), subtype (1B), offset (4B), size (4B), label (16s), flags (4B)
        self.part_fmt = "<HBBII16sI"

    def extract(self, firmware_path: str):
        if not os.path.exists(firmware_path):
            return None

        with open(firmware_path, "rb") as f:
            data = f.read()

        if len(data) < 8:
            return {"chip": "ESP32", "segments": [], "partitions": [], "raw_binary": data, "is_unified_flash": False}

        # Detect structural type: Unified dump vs standalone partition component
        is_unified_flash = False
        base_offset = 0x0
        
        # Standard hardware dumps start with blank padding, holding the real header magic at offset 0x1000
        if len(data) > 0x1000 and data[0x1000:0x1001] in (b"\xE9", b"\xEA"):
            is_unified_flash = True
            base_offset = 0x1000
        elif data[0:1] in (b"\xE9", b"\xEA"):
            is_unified_flash = False
            base_offset = 0x0

        segments = []
        entry = 0
        
        try:
            hdr_bytes = data[base_offset : base_offset + 8]
            if len(hdr_bytes) == 8:
                magic, seg_count, mode, config, entry = struct.unpack(self.header_fmt, hdr_bytes)
                
                # Extract Segments based on header information rules safely
                offset = base_offset + 24  # Standard size of header + extension properties
                for _ in range(min(seg_count, 16)):  # Sanity constraint cap to avoid corruption looping
                    if offset + 8 > len(data):
                        break
                    load_addr, length = struct.unpack("<II", data[offset : offset + 8])
                    if offset + 8 + length > len(data):
                        break
                    
                    segments.append({
                        "addr": hex(load_addr),
                        "data": data[offset + 8 : offset + 8 + length]
                    })
                    offset += 8 + length
        except Exception:
            pass

        # Locate Partition Table
        partitions = self._find_partitions(data, is_unified_flash)

        return {
            "chip": "ESP32",
            "entry_point": hex(entry),
            "segments": segments,
            "partitions": partitions,
            "raw_binary": data,
            "is_unified_flash": is_unified_flash
        }

    def _find_partitions(self, data: bytes, is_unified_flash: bool):
        partitions = []
        if not is_unified_flash:
            return partitions

        # Common physical partition table offsets for ESP32 architectures
        for offset in [0x8000, 0x9000]:
            curr = offset
            while curr + 32 <= len(data):
                row = data[curr : curr + 32]
                
                # Check for clean end boundaries markers
                if row == b"\xFF" * 32 or row == b"\x00" * 32:
                    break
                
                try:
                    magic, p_type, p_subtype, p_offset, p_size, label_raw, flags = struct.unpack(self.part_fmt, row)
                    
                    # Validate against the official 0x50AA magic marker to ensure strict alignment
                    if magic == 0x50AA and p_type in (0x00, 0x01) and 0 < p_size < len(data):
                        name = label_raw.split(b"\x00")[0].decode("ascii", errors="ignore").strip()
                        partitions.append({
                            "name": name,
                            "type": p_type,
                            "subtype": p_subtype,
                            "offset": hex(p_offset),
                            "size": p_size,
                            "flags": flags
                        })
                    elif magic == 0xEFEB:
                        # Official MD5 entry trailing block encountered
                        break
                    else:
                        break
                except Exception:
                    break
                curr += 32
                
            if partitions:
                break
        return partitions