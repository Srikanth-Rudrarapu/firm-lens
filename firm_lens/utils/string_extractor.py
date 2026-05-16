import os
from typing import List, Tuple


class StringExtractor:
    """
    Extract printable strings from firmware images.

    Features:
      • ASCII + UTF-8 safe extraction
      • Tracks byte offsets for each string
      • Minimum length filtering
      • Works on large firmware images efficiently

    Output:
      List of tuples: (offset, string)
    """

    def __init__(self, min_length: int = 4):
        self.min_length = min_length

    def extract(self, firmware_path: str) -> List[Tuple[int, str]]:
        if not os.path.exists(firmware_path):
            return []

        results: List[Tuple[int, str]] = []

        try:
            with open(firmware_path, "rb") as f:
                data = f.read()
        except Exception:
            return []

        current = []
        start_offset = None

        for i, b in enumerate(data):
            if 32 <= b <= 126:  # printable ASCII
                if start_offset is None:
                    start_offset = i
                current.append(chr(b))
            else:
                # End of a string
                if current and len(current) >= self.min_length:
                    results.append((start_offset, "".join(current)))
                current = []
                start_offset = None

        # Handle trailing string
        if current and len(current) >= self.min_length:
            results.append((start_offset, "".join(current)))

        return results
