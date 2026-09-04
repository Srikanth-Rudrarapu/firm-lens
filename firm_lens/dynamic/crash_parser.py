import re

class CrashParser:
    def __init__(self):
        self.panic_signature = re.compile(
            r"Guru Meditation Error:\s*Core\s+\d+\s+panic'ed\s*\((.*?)\)", 
            re.IGNORECASE
        )
        self.register_signature = re.compile(
            r"EPC1\s*:\s*(0x[0-9a-fA-F]+)", 
            re.IGNORECASE
        )
        self.exccause_signature = re.compile(
            r"EXCCAUSE\s*:\s*(?:0x)?([0-9a-fA-F]+)", 
            re.IGNORECASE
        )

    def parse_log(self, crash_log: list) -> dict:
        if not crash_log:
            return {"status": "Clean", "details": "No hardware faults detected."}

        fault_type = "Catastrophic Memory Corruption (Garbled Panic)"
        epc1_address = "Overwritten / Unrecoverable"
        specific_cause_found = False

        for line in crash_log:
            # 1. Guru Meditation Panic Reason (e.g. LoadProhibited)
            panic_match = self.panic_signature.search(line)
            if panic_match:
                fault_type = panic_match.group(1).strip()
                specific_cause_found = True

            # 2. EPC1 Register
            reg_match = self.register_signature.search(line)
            if reg_match:
                epc1_address = reg_match.group(1).strip()

            # 3. Dynamic Stack Smashing Pattern (e.g. 0x41414141)
            corrupted_ptr_match = re.search(r'(0x(?:41){2,4})', line, re.IGNORECASE)
            if corrupted_ptr_match:
                epc1_address = f"{corrupted_ptr_match.group(1)} (Dynamic Payload Signature)"
                fault_type = "Instruction Pointer Overwrite (Stack Smashing)"
                specific_cause_found = True

            # 4. EXCCAUSE (Only used as a fallback if no descriptive panic reason was matched)
            if "EXCCAUSE" in line and not specific_cause_found:
                cause_match = self.exccause_signature.search(line)
                if cause_match:
                    raw_cause = cause_match.group(1).strip()
                    hex_cause = raw_cause if raw_cause.lower().startswith("0x") else f"0x{raw_cause}"
                    fault_type = f"Hardware Exception (Cause Code: {hex_cause})"

            # 5. Watchdog / Software Reset Events
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