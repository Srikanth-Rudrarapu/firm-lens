import socket
import time
from rich.console import Console

console = Console()

class WiFiFuzzer:
    def __init__(self, target_ip: str, target_port: int = 80, crash_event=None):
        self.target_ip = target_ip
        self.target_port = target_port
        self.crash_event = crash_event

    def send_tcp_payload(self, payload: bytes):
        """Send a raw payload to the target IP and port."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect((self.target_ip, self.target_port))
                s.sendall(payload)
        except Exception as e:
            console.print(f"[dim red]Socket Error: {str(e)}[/dim red]")

    def run(self):
        console.print(f"[info]Initializing Wi-Fi Network Fuzzer against {self.target_ip}:{self.target_port}...[/info]")
        console.print("[info]Waiting 5 seconds for macOS Wi-Fi routing to stabilize...[/info]")
        time.sleep(5)
        
        # 1. HTTP Oversized URI (Buffer Overflow in URL Parser)
        long_uri = b"GET /" + (b"A" * 1000) + b" HTTP/1.1\r\nHost: " + self.target_ip.encode() + b"\r\n\r\n"
        
        # 2. HTTP Format String Injection in Headers
        fmt_string = b"GET / HTTP/1.1\r\nHost: %x%x%x%x%n%s%s\r\n\r\n"
        
        # 3. Raw TCP Junk Flood (Test for unhandled socket exceptions)
        junk_flood = b"\x00\xFF\xAA\x55" * 500

        payloads = [
            ("Oversized HTTP URI", long_uri),
            ("HTTP Header Format String", fmt_string),
            ("Raw TCP Socket Flood", junk_flood)
        ]

        for name, payload in payloads:
            if self.crash_event and self.crash_event.is_set():
                console.print("[warning]Target already down. Halting network fuzzing.[/warning]")
                break
                
            console.print(f"[cyan]  [+] Injecting Network Payload: {name}...[/cyan]")
            self.send_tcp_payload(payload)
            time.sleep(2) # Wait for device to process and potentially crash