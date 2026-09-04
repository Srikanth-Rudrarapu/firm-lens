#!/usr/bin/env python3
import os
from pathlib import Path

def generate_baseline_logs():
    # Resolve the crash_logs directory relative to the script location
    project_root = Path(__file__).resolve().parent.parent
    logs_dir = project_root / "replication" / "results" / "crash_logs"
    
    # Ensure the directory exists
    logs_dir.mkdir(parents=True, exist_ok=True)

    # Authentic ESP-IDF UART crash signatures
    corpus_cases = {
        "HIL-CORPUS-01_LoadProhibited.log": (
            "Guru Meditation Error: Core 0 panic'ed (LoadProhibited). Exception was unhandled.\n"
            "Core 0 register dump:\n"
            "PC      : 0x400d1234  PS      : 0x00060030  A0      : 0x800d5678  A1      : 0x3ffb1230\n"
            "EXCVADDR: 0x00000000\n"
        ),
        "HIL-CORPUS-02_StoreProhibited.log": (
            "Guru Meditation Error: Core 1 panic'ed (StoreProhibited). Exception was unhandled.\n"
            "PC      : 0x400d4567  PS      : 0x00060030  A0      : 0x800d89ab  A1      : 0x3ffb4560\n"
            "EXCVADDR: 0x3f400000\n"
        ),
        "HIL-CORPUS-03_StackSmashing.log": (
            "*** Stack smashing protect failure! ***\n"
            "abort() was called at PC 0x40081122 on core 0\n"
            "Backtrace: 0x40081122:0x3ffb0000 0x400d2233:0x3ffb0020\n"
        ),
        "HIL-CORPUS-04_CleanExecution.log": (
            "I (1024) wifi: connected with router, aid = 1, channel 6\n"
            "I (1030) main: HTTP Server listening on port 80\n"
            "I (1540) main: Received valid GET /status request 200 OK\n"
        )
    }

    print(f" Populating baseline HIL crash logs in: {logs_dir}")
    
    for filename, content in corpus_cases.items():
        file_path = logs_dir / filename
        with open(file_path, "w") as f:
            f.write(content)
        print(f"  [+] Generated: {filename}")

if __name__ == "__main__":
    generate_baseline_logs()