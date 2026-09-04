import struct
import pytest
from firm_lens.analyzers.secure_boot_analyzer import SecureBootAnalyzer

def test_secure_boot_unsigned_image():
    analyzer = SecureBootAnalyzer()
    
    # Construct synthetic unsigned ESP32 app binary (magic 0xE9, no 0xE7 signature block)
    raw_app = bytearray(b"\x00" * 4096)
    raw_app[0:2] = struct.pack("<BB", 0xE9, 4)
    
    findings = analyzer.run_with_map("test_app.bin", {"raw_binary": bytes(raw_app)})
    finding_ids = [f.id for f in findings]
    
    assert "FL-BOOT-HEADER" in finding_ids
    assert "FL-BOOT-SIGNATURE" in finding_ids

def test_secure_boot_signed_v2_image():
    analyzer = SecureBootAnalyzer()
    
    # Construct synthetic signed ESP32 binary with 0xE7 signature sector magic in trailer
    raw_app = bytearray(b"\x00" * 8192)
    raw_app[0:2] = struct.pack("<BB", 0xE9, 4)
    
    # Insert Secure Boot V2 signature magic in trailer
    raw_app[-4096] = 0xE7
    
    findings = analyzer.run_with_map("test_signed.bin", {"raw_binary": bytes(raw_app)})
    finding_ids = [f.id for f in findings]
    
    assert "FL-BOOT-HEADER" in finding_ids
    assert "FL-BOOT-SIGNATURE" not in finding_ids

def test_secure_boot_flash_dump():
    analyzer = SecureBootAnalyzer()
    
    # Construct synthetic 4MB flash dump with bootloader header at offset 0x1000
    raw_flash = bytearray(b"\xFF" * 0x10000)
    raw_flash[0x1000:0x1002] = struct.pack("<BB", 0xE9, 3)
    
    findings = analyzer.run_with_map("test_flash.bin", {"raw_binary": bytes(raw_flash)})
    finding_ids = [f.id for f in findings]
    
    assert "FL-BOOT-HEADER" in finding_ids
    assert "FL-BOOT-SIGNATURE" in finding_ids