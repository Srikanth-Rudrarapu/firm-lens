import re
from typing import List, Tuple

class StringExtractor:
    """
    Industrial-grade High-Performance String Carving Engine.
    Leverages an optimized regular expression execution matrix to extract 
    printable ASCII streams from massive raw binary buffers safely and instantly.
    """

    def __init__(self, min_length: int = 4):
        self.min_length = min_length
        # Pre-compile the pattern to process binary data streams at the native C-level.
        # Matches printable ASCII characters ranging from space (0x20) to tilde (0x7E).
        self.pattern = re.compile(rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}')

    def extract_from_bytes(self, data: bytes) -> List[Tuple[int, str]]:
        """
        Scans a raw binary byte array and extracts strings alongside their exact offsets.
        Optimized to process massive data footprints with low garbage-collection impact.
        
        Returns:
            A list of tuples containing (byte_offset, decoded_ascii_string).
        """
        if not data or not isinstance(data, (bytes, bytearray)):
            return []

        findings: List[Tuple[int, str]] = []
        
        # re.finditer handles large 4MB arrays natively with minimal memory allocations
        for match in self.pattern.finditer(data):
            offset = match.start()
            match_bytes = match.group()
            
            # Avoiding computing decoding logic on long streams of identical 
            # repetitive padding bytes (e.g., long sequences of spaces or filler characters)
            if len(match_bytes) > 64 and len(set(match_bytes)) < 4:
                continue
                
            try:
                # Extract address offset and decode byte content safely
                decoded_str = match_bytes.decode("ascii", errors="ignore").strip()
                if decoded_str:
                    findings.append((offset, decoded_str))
            except Exception:
                continue

        return findings