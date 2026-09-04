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
        device_ready = False

        panic_patterns = (
            "guru meditation error",
            "abort() was called",
            "stack smashing protect",
            "corrupt heap",
            "double exception",
            "backtrace:",
            "loadprohibited",
            "storeprohibited",
            "instructionfetcherror",
            "assert failed:",
        )

        reboot_patterns = (
            "rst:0x",
            "boot: 0x",
            "configsip:",
            "multicore bootloader",
            "entry 0x",
            "boot: esp-idf",
        )

        while self.is_monitoring and self.serial_conn and self.serial_conn.is_open:
            try:
                raw_line = self.serial_conn.readline()
                if not raw_line:
                    continue

                line = raw_line.decode("utf-8", errors="ignore").strip()
                if not line:
                    continue

                line_lower = line.lower()

                if not self.crash_detected.is_set():
                    console.print(f"[dim white]ESP32> {line}[/dim white]")

                if not device_ready:
                    if not any(pat in line_lower for pat in reboot_patterns):
                        device_ready = True

                if any(sig in line_lower for sig in panic_patterns) or "414141" in line_lower:
                    self.crash_detected.set()
                elif device_ready and any(sig in line_lower for sig in reboot_patterns):
                    self.crash_detected.set()

                if self.crash_detected.is_set():
                    self.crash_log.append(line)
                    if len(self.crash_log) >= 15:
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
        if hasattr(self, "thread"):
            self.thread.join(timeout=2)
        if self.serial_conn and self.serial_conn.is_open:
            self.serial_conn.close()