import os
import tempfile
import pytest

from firm_lens.analyzers.secrets_analyzer import SecretsAnalyzer


def test_wifi_struct_credential_extraction():
    """
    Verify SecretsAnalyzer detects 32-byte SSID + 64-byte null-terminated PSK structs
    and maps them to FL-CRED-STRUCT (CWE-798 / CWE-259).
    """
    # 4 KB test buffer
    raw_flash = bytearray(b"\x00" * 4096)

    # Embed Wi-Fi Config Struct at offset 0x200
    # SSID: 32 bytes (null-padded)
    ssid = b"OfficeNet\x00" + (b"\x00" * (32 - len(b"OfficeNet\x00")))
    # PSK: 64 bytes (null-terminated)
    psk = b"Passw0rd123!\x00" + (b"\x00" * (64 - len(b"Passw0rd123!\x00")))

    offset = 0x200
    raw_flash[offset : offset + 32] = ssid
    raw_flash[offset + 32 : offset + 96] = psk

    firmware_map = {
        "raw_binary": bytes(raw_flash),
        "partitions": []
    }

    analyzer = SecretsAnalyzer()
    findings = analyzer.run_with_map("synthetic_test.bin", firmware_map)

    assert isinstance(findings, list)
    finding_ids = [f.id for f in findings]
    assert "FL-CRED-STRUCT" in finding_ids

    wifi_finding = next(f for f in findings if f.id == "FL-CRED-STRUCT")
    assert wifi_finding.severity == "Critical"
    assert "CWE-798" in wifi_finding.cwes
    assert "OfficeNet" in wifi_finding.evidence
    assert "Passw0rd123!" in wifi_finding.evidence


def test_hardcoded_token_pattern_detection():
    """
    Verify SecretsAnalyzer identifies explicit key-value assignments
    (e.g., token=SecretToken12345).
    """
    raw_flash = bytearray(b"\x00" * 2048)
    token_str = b"api_key=Secr3tToken123!Value\x00"
    raw_flash[0x100 : 0x100 + len(token_str)] = token_str

    firmware_map = {
        "raw_binary": bytes(raw_flash),
        "partitions": []
    }

    analyzer = SecretsAnalyzer()
    findings = analyzer.run_with_map("synthetic_test.bin", firmware_map)

    assert isinstance(findings, list)
    finding_ids = [f.id for f in findings]
    assert "FL-CRED-HARDCODED" in finding_ids