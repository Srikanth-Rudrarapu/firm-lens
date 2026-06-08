import time
from rich.console import Console

console = Console()

class UARTFuzzer:
    def __init__(self, serial_connection, crash_event):
        self.serial = serial_connection
        self.crash_event = crash_event # Allows fuzzer to stop if device dies

    def run(self):
        console.print("[info]Waiting for ESP32 boot sequence to stabilize (3 seconds)...[/info]")
        time.sleep(3)
        
        console.print("[info]Initializing UART Fuzzing Engine...[/info]")
        
        payloads = [
            b"A" * 10,
            b"A" * 32,
            b"A" * 100,
            b"%x %x %x %s %s %s %s", 
            b"A" * 1000 
        ]
        
        for payload in payloads:
            if self.crash_event.is_set():
                break
                
            console.print(f"[cyan]  [+] Injecting {len(payload)}-byte payload...[/cyan]")
            self.serial.write(payload)
            self.serial.write(b'\n')
            time.sleep(1.5)