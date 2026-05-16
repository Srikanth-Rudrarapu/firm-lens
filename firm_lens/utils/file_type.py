import os


class FileTypeDetector:
    """
    Secure file type detection for firmware analysis.

    Prevents PDFs, images, documents, scripts, and other non‑firmware files
    from being analyzed. Also detects common firmware container formats
    such as ELF, HEX, BIN, and ESP32 images.
    """

    @staticmethod
    def detect(firmware_path: str) -> str:
        if not os.path.isfile(firmware_path):
            return "not_found"

        try:
            with open(firmware_path, "rb") as f:
                header = f.read(128)
        except Exception:
            return "unreadable"

        # Empty file
        if len(header) == 0:
            return "empty"

        # ------------------------------------------------------------
        # Document / script formats (blocked)
        # ------------------------------------------------------------
        if header.startswith(b"%PDF"):
            return "pdf"

        if header.startswith(b"\x89PNG\r\n\x1a\n"):
            return "png"

        if header.startswith(b"\xFF\xD8\xFF"):
            return "jpeg"

        # Office formats (ZIP-based)
        if header.startswith(b"PK\x03\x04"):
            # Could be DOCX, XLSX, PPTX, or OTA ZIP
            # We treat ZIP as firmware bundle only if user explicitly passes it
            return "zip"

        # Python scripts
        if header.startswith(b"#!/usr/bin/env python") or b"import " in header:
            return "script"

        # Shell scripts
        if header.startswith(b"#!/bin/bash") or header.startswith(b"#!/bin/sh"):
            return "script"

        # ------------------------------------------------------------
        # Firmware formats
        # ------------------------------------------------------------

        # ELF firmware
        if header.startswith(b"\x7fELF"):
            return "elf"

        # Intel HEX (ASCII ':' at start)
        if header.startswith(b":"):
            return "hex"

        # ESP32 image magic at offset 0x0 (rare) or 0x1000 (common)
        if header[0:1] in (b"\xE9", b"\xEA"):
            return "esp32"

        # STM32 raw binaries often start with vector table (stack pointer)
        # First 4 bytes: initial SP (RAM address, typically 0x2000xxxx)
        if len(header) >= 4:
            sp = int.from_bytes(header[0:4], "little", signed=False)
            if 0x20000000 <= sp <= 0x20050000:
                return "stm32"

        # ------------------------------------------------------------
        # Fallback
        # ------------------------------------------------------------
        return "bin"
