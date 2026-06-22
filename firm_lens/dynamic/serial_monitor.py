import serial
import threading
import time
from rich.console import Console

console = Console()

class FirmLensHILMonitor:
    def __init__(self, port: str, baudrate: int = 115200):
        self.port = port
        self.baudrate = baudrate
        self.serial_conn = None
        self.is_monitoring = False
        self.crash_detected = threading.Event()
        self.crash_log = []

    def connect(self) -> bool:
        try:
            self.serial_conn = serial.Serial(self.port, self.baudrate, timeout=1)
            self.serial_conn.setDTR(False)
            self.serial_conn.setRTS(False)
            time.sleep(0.1)
            self.serial_conn.setDTR(True)
            self.serial_conn.setRTS(True)
            return True
        except Exception as e:
            console.print(f"[bold red]Hardware Connection Fault: {str(e)}[/bold red]")
            return False

    def _monitor_loop(self):
        app_has_started = False
        while self.is_monitoring and self.serial_conn.is_open:
            try:
                line = self.serial_conn.readline().decode('utf-8', errors='ignore').strip()
                if line:
                    if not self.crash_detected.is_set():
                        console.print(f"[dim white]ESP32> {line}[/dim white]")
                    
                    if "FirmLens HIL Target Active" in line:
                        app_has_started = True

                    if ("Guru Meditation Error" in line or "abort() was called" in line or 
                        "414141" in line or 
                        (app_has_started and ("boot: ESP-IDF" in line or "Multicore bootloader" in line))):
                        self.crash_detected.set()
                    
                    if self.crash_detected.is_set():
                        self.crash_log.append(line)
                        if len(self.crash_log) > 10:
                            self.is_monitoring = False
            except Exception:
                pass

    def start(self):
        self.is_monitoring = True
        self.crash_detected.clear()
        self.crash_log = []
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.is_monitoring = False
        if hasattr(self, 'thread'):
            self.thread.join(timeout=2)
        if self.serial_conn and self.serial_conn.is_open:
            self.serial_conn.close()    