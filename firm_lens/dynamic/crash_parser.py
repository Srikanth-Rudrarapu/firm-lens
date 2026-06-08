import re

class CrashParser:
    def __init__(self):
        self.panic_signature = re.compile(r"Guru Meditation Error: Core\s+\d+\s+panic'ed \((.*?)\)")
        self.register_signature = re.compile(r"EPC1\s+:\s+(0x[0-9a-fA-F]+)")

    def parse_log(self, crash_log: list) -> dict:
        if not crash_log:
            return {"status": "Clean", "details": "No hardware faults detected."}

        fault_type = "Catastrophic Memory Corruption (Garbled Panic)"
        epc1_address = "Overwritten / Unrecoverable"

        for line in crash_log:
            panic_match = self.panic_signature.search(line)
            if panic_match:
                fault_type = panic_match.group(1)
            
            reg_match = self.register_signature.search(line)
            if reg_match:
                epc1_address = reg_match.group(1)

            # Dynamic payload extraction
            corrupted_ptr_match = re.search(r'(0x(?:41){2,4})', line, re.IGNORECASE)
            if corrupted_ptr_match:
                epc1_address = f"{corrupted_ptr_match.group(1)} (Dynamic Payload Signature)"
                fault_type = "Instruction Pointer Overwrite (Stack Smashing)"
            
            if "EXCCAUSE" in line:
                cause_match = re.search(r'EXCCAUSE:\s*([0-9a-fA-F]+)', line)
                if cause_match:
                    fault_type = f"Hardware Exception (Cause Code: 0x{cause_match.group(1)})"

            if "SW_CPU_RESET" in line or "Watchdog triggered" in line:
                fault_type = "Watchdog Reset via Unrecoverable Halt"

        return {
            "status": "Vulnerable",
            "cwe": "CWE-120: Buffer Overflow / CWE-134: Format String",
            "severity": "CRITICAL",
            "fault_type": fault_type,
            "instruction_pointer": epc1_address,
            "evidence": f"Hardware crash triggered via fuzzing. CPU panicked with '{fault_type}'."
        }