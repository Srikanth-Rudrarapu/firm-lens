import struct
import os

class ESP32Extractor:
    """
    Pure Extraction Layer: Transforms binary data into a structured Firmware Map.
    This file handles NO analysis; it only provides the 'what' and 'where'.
    """
    
    def __init__(self):
        # esp_image_header_t (8 bytes core)
        self.header_fmt = "<BBBB I" 
        # partition_entry_t (32 bytes)
        self.part_fmt = "<2sBBII16sI" 

    def extract(self, firmware_path: str):
        if not os.path.exists(firmware_path):
            return None

        with open(firmware_path, "rb") as f:
            data = f.read()

        # 1. Parse Header
        magic, seg_count, mode, config, entry = struct.unpack(self.header_fmt, data[:8])
        
        # 2. Extract Segments (The actual code/data blocks)
        segments = []
        offset = 24 # Header + Padding
        for _ in range(seg_count):
            load_addr, length = struct.unpack("<II", data[offset:offset+8])
            segments.append({
                "addr": hex(load_addr),
                "data": data[offset+8 : offset+8+length]
            })
            offset += 8 + length

        # 3. Locate Partition Table (Scanning for 0xAA 0x50)
        partitions = self._find_partitions(data)

        # This dictionary is the "Contract" passed to your Analyzers
        return {
            "chip": "ESP32",
            "entry_point": hex(entry),
            "segments": segments,
            "partitions": partitions,
            "raw_binary": data
        }

    def _find_partitions(self, data: bytes):
        partitions = []
        # Common ESP32 partition table offsets
        for offset in [0x8000, 0x9000, 0x10000]:
            if data[offset:offset+2] == b"\xAA\x50":
                curr = offset
                while data[curr:curr+2] == b"\xAA\x50":
                    entry = struct.unpack(self.part_fmt, data[curr:curr+32])
                    partitions.append({
                        "name": entry[5].decode().strip("\x00"),
                        "offset": entry[3],
                        "size": entry[4]
                    })
                    curr += 32
                break
        return partitions