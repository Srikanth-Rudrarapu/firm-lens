import pytest
from firm_lens.dynamic.crash_parser import CrashParser


def test_crash_parser_guru_meditation_panic():
    """Verify CrashParser intercepts Guru Meditation Error and extracts register state."""
    parser = CrashParser()

    sample_esp32_panic = [
        "Guru Meditation Error: Core  0 panic'ed (LoadProhibited). Exception was unhandled.",
        "Core  0 register dump:",
        "PC      : 0x400d1234  PS      : 0x00060030  A0      : 0x800d5678  A1      : 0x3ffb1230",
        "EPC1    : 0x400d9876  EPC2    : 0x00000000  EPC3    : 0x00000000  EPC4    : 0x00000000",
        "EXCCAUSE: 0x0000001c",
        "Backtrace: 0x400d1234:0x3ffb1230 0x400d5678:0x3ffb1250",
    ]

    result = parser.parse_log(sample_esp32_panic)

    assert result["status"] == "Vulnerable"
    assert result["severity"] == "CRITICAL"
    assert "LoadProhibited" in result["fault_type"] or "0x0000001c" in result["fault_type"]
    assert result["instruction_pointer"] == "0x400d9876"
    assert "CWE-120" in result["cwe"] or "CWE-134" in result["cwe"]


def test_crash_parser_stack_smashing_signature():
    """Verify CrashParser detects instruction pointer overwrite (0x41414141 pattern)."""
    parser = CrashParser()

    sample_smash_log = [
        "Guru Meditation Error: Core  0 panic'ed (Unhandled debug exception)",
        "EPC1    : 0x41414141",
        "Backtrace: 0x41414141:0x3ffb1230",
    ]

    result = parser.parse_log(sample_smash_log)

    assert result["status"] == "Vulnerable"
    assert "0x41414141" in result["instruction_pointer"]
    assert "Stack Smashing" in result["fault_type"] or "Instruction Pointer Overwrite" in result["fault_type"]


def test_crash_parser_clean_log():
    """Verify CrashParser returns clean status when no panic lines are present."""
    parser = CrashParser()
    result = parser.parse_log([])

    assert result["status"] == "Clean"
    assert "No hardware faults detected" in result["details"]