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

        # Check for ESP32 Main Header Magic (0xE9)
        if len(header) >= 1 and header[0:1] == b"\xE9":
            return "esp32"

        # Fallback check for raw STM32 (Vector table stack pointers)
        if len(header) >= 4:
            sp = int.from_bytes(header[0:4], "little", signed=False)
            if 0x20000000 <= sp <= 0x20050000:
                return "stm32"

        return "bin"