import os


def read_bytes(path: str, offset: int, length: int) -> bytes:
    """
    Safely read a slice of bytes from a firmware image.

    Features:
      • Rejects negative offsets
      • Rejects negative lengths
      • Prevents reading beyond file size
      • Returns empty bytes on invalid ranges
      • Never throws unhandled exceptions

    This utility is used by analyzers that need to inspect specific
    regions of the firmware (bootloader, app header, partition table, etc.).
    """

    if offset < 0 or length <= 0:
        return b""

    if not os.path.exists(path):
        return b""

    try:
        file_size = os.path.getsize(path)
    except OSError:
        return b""

    # Prevent reading beyond file boundary
    if offset >= file_size:
        return b""

    end = offset + length
    if end > file_size:
        end = file_size
        length = end - offset

    try:
        with open(path, "rb") as f:
            f.seek(offset)
            return f.read(length)
    except Exception:
        return b""
