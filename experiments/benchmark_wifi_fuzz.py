#!/usr/bin/env python3
import csv
import os
import socket
import sys
import time
from pathlib import Path

# Add project root to sys.path to resolve 'firm_lens' imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from firm_lens.dynamic.crash_parser import CrashParser
from firm_lens.dynamic.serial_monitor import FirmLensHILMonitor

RESULTS_DIR = PROJECT_ROOT / "replication" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
CSV_OUT = RESULTS_DIR / "wifi_fuzz_benchmark_data.csv"


def send_network_payload(target_ip: str, target_port: int, payload: bytes, timeout: float = 2.0) -> tuple[bool, str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target_ip, target_port))
            s.sendall(payload)
            try:
                response = s.recv(1024)
                return True, f"Received {len(response)} bytes response"
            except socket.timeout:
                return True, "Payload sent (No response / Timeout)"
    except Exception as e:
        return False, f"Socket Exception: {type(e).__name__} - {str(e)}"


def run_wifi_fuzz_benchmark(target_ip: str, target_port: int = 80, serial_port: str = "/dev/cu.usbserial-0001"):
    print(f" Initializing Wi-Fi Network Fuzzing against {target_ip}:{target_port}")
    print(f" Attaching HIL serial monitor on {serial_port} for dynamic fault capture...")

    monitor = FirmLensHILMonitor(port=serial_port, baudrate=115200)
    parser = CrashParser()
    serial_attached = monitor.connect()
    
    if serial_attached:
        monitor.start()
        time.sleep(1.0)
    else:
        print("[!] Serial port not accessible. Running network fuzzing without live UART monitoring.")

    test_vectors = [
        ("WIFI-FUZZ-001", "HTTP Baseline Probe", b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n"),
        ("WIFI-FUZZ-002", "Oversized URI Buffer (1000B)", b"GET /" + (b"A" * 1000) + b" HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n"),
        ("WIFI-FUZZ-003", "HTTP Header Format String", b"GET / HTTP/1.1\r\nHost: %x%x%x%x%n%s%s\r\n\r\n"),
        ("WIFI-FUZZ-004", "Malformed Content-Length Smuggling", b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n"),
        ("WIFI-FUZZ-005", "Raw TCP Binary Junk Flood (2000B)", b"\x00\xFF\xAA\x55" * 500),
    ]

    records = []

    for test_id, description, payload in test_vectors:
        t0 = time.perf_counter()
        delivery_ok, socket_status = send_network_payload(target_ip, target_port, payload)
        time.sleep(1.0)
        t1 = time.perf_counter()

        crash_status = "Clean"
        fault_type = "None"
        instruction_pointer = "N/A"

        if serial_attached and monitor.crash_detected.is_set():
            parsed_crash = parser.parse_log(list(monitor.crash_log))
            crash_status = parsed_crash.get("status", "Vulnerable")
            fault_type = parsed_crash.get("fault_type", "Unknown Panic")
            instruction_pointer = parsed_crash.get("instruction_pointer", "N/A")
            monitor.crash_detected.clear()
            monitor.crash_log = []

        record = {
            "test_case_id": test_id,
            "description": description,
            "payload_bytes": len(payload),
            "latency_sec": round(t1 - t0, 4),
            "network_delivered": delivery_ok,
            "network_status": socket_status,
            "hardware_state": crash_status,
            "fault_type": fault_type,
            "instruction_pointer": instruction_pointer
        }
        records.append(record)
        print(f" [+] {test_id} ({description}): Delivered={delivery_ok} | State={crash_status} | Fault={fault_type}")

    if serial_attached:
        monitor.stop()

    with open(CSV_OUT, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "test_case_id", "description", "payload_bytes", "latency_sec",
            "network_delivered", "network_status", "hardware_state", "fault_type", "instruction_pointer"
        ])
        writer.writeheader()
        writer.writerows(records)

    print(f"\n Wi-Fi fuzzing benchmark completed. Saved to: {CSV_OUT}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 experiments/benchmark_wifi_fuzz.py <ESP32_IP_ADDRESS> [PORT] [SERIAL_PORT]")
        print("Example: python3 experiments/benchmark_wifi_fuzz.py 192.168.4.1 80 /dev/cu.usbserial-0001")
        sys.exit(1)

    ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    ser = sys.argv[3] if len(sys.argv) > 3 else "/dev/cu.usbserial-0001"
    run_wifi_fuzz_benchmark(ip, port, ser)