import os

class FileTypeDetector:
    """
    Secure file type detection for firmware analysis.
    Prevents non‑firmware files from being processed and identifies embedded architectures.
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

        if len(header) == 0:
            return "empty"

        # Content Guardrails
        if header.startswith(b"%PDF"):
            return "pdf"
        if header.startswith(b"\x89PNG\r\n\x1a\n"):
            return "png"
        if header.startswith(b"\xFF\xD8\xFF"):
            return "jpeg"
        if header.startswith(b"PK\x03\x04"):
            return "zip"
        if header.startswith(b"#!/usr/bin/env python") or b"import " in header:
            return "script"
        if header.startswith(b"#!/bin/bash") or header.startswith(b"#!/bin/sh"):
            return "script"

        # Firmware Executables Check
        if header.startswith(b"\x7fELF"):
            return "elf"
        if header.startswith(b":"):
            return "hex"
        
        # Espressif Boot Image Validation (0xE9 Boot Magic)
        if len(header) >= 4 and header[0:1] == b"\xE9":
            # Extra verification: Validate that segment count and flash configs look realistic
            if header[1] <= 16:  # Standard Espressif layouts rarely exceed 16 segments
                return "esp32"

        return "bin"