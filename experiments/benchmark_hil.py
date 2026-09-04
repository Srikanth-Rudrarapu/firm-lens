#!/usr/bin/env python3
import csv
import glob
import json
import os
import sys
import time
from pathlib import Path

from firm_lens.dynamic.crash_parser import CrashParser
from firm_lens.dynamic.serial_monitor import FirmLensHILMonitor


RESULTS_DIR = Path(__file__).resolve().parent.parent / "replication" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

CSV_OUT = RESULTS_DIR / "hil_benchmark_data.csv"
JSON_OUT = RESULTS_DIR / "hil_evaluation_summary.json"


def find_default_port() -> str:
    patterns = [
        "/dev/cu.usbserial*",
        "/dev/cu.wchusbserial*",
        "/dev/cu.SLAB_USBtoUART*",
        "/dev/cu.usbmodem*",
        "/dev/ttyUSB*",
        "/dev/ttyACM*",
    ]

    for pattern in patterns:
        matches = glob.glob(pattern)
        if matches:
            return matches[0]

    return ""


def run_offline_corpus_evaluation():
    print(" Running Offline Crash Corpus Verification Benchmark...")

    parser = CrashParser()

    corpus_cases = [
        {
            "id": "HIL-CORPUS-01",
            "name": "Guru Meditation - LoadProhibited",
            "expected_fault": "LoadProhibited",
            "log": [
                "Guru Meditation Error: Core 0 panic'ed (LoadProhibited). Exception was unhandled.",
                "Core 0 register dump:",
                "PC      : 0x400d1234  PS      : 0x00060030  A0      : 0x800d5678  A1      : 0x3ffb1230",
                "EXCVADDR: 0x00000000",
            ],
        },
        {
            "id": "HIL-CORPUS-02",
            "name": "Guru Meditation - StoreProhibited",
            "expected_fault": "StoreProhibited",
            "log": [
                "Guru Meditation Error: Core 1 panic'ed (StoreProhibited). Exception was unhandled.",
                "PC      : 0x400d4567  PS      : 0x00060030  A0      : 0x800d89ab  A1      : 0x3ffb4560",
                "EXCVADDR: 0x3f400000",
            ],
        },
        {
            "id": "HIL-CORPUS-03",
            "name": "Stack Smashing / Canary Corruption",
            "expected_fault": "StackSmashing",
            "log": [
                "*** Stack smashing protect failure! ***",
                "abort() was called at PC 0x40081122 on core 0",
                "Backtrace: 0x40081122:0x3ffb0000 0x400d2233:0x3ffb0020",
            ],
        },
        {
            "id": "HIL-CORPUS-04",
            "name": "Clean Operational Execution",
            "expected_fault": "None",
            "log": [
                "I (1024) wifi: connected with router, aid = 1, channel 6",
                "I (1030) main: HTTP Server listening on port 80",
                "I (1540) main: Received valid GET /status request 200 OK",
            ],
        },
    ]

    records = []
    correct_classifications = 0

    for item in corpus_cases:
        t0 = time.perf_counter()

        parsed = parser.parse_log(item["log"])

        t1 = time.perf_counter()

        detected_fault = parsed.get("fault_type", "None")
        detected_status = parsed.get("status", "Clean")

        is_correct = (
            detected_fault == item["expected_fault"]
            or item["expected_fault"] in str(detected_fault)
        )

        if is_correct:
            correct_classifications += 1

        record = {
            "test_case_id": item["id"],
            "test_name": item["name"],
            "expected_fault": item["expected_fault"],
            "detected_fault": detected_fault,
            "status": detected_status,
            "latency_ms": round((t1 - t0) * 1000, 4),
            "match": is_correct,
        }

        records.append(record)

        print(
            f"  {item['id']} ({item['name']}): "
            f"Expected={item['expected_fault']} | "
            f"Detected={detected_fault} | "
            f"Match={is_correct}"
        )

    accuracy_pct = (
        correct_classifications / len(corpus_cases) * 100
        if corpus_cases
        else 0.0
    )

    with open(CSV_OUT, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "test_case_id",
                "test_name",
                "expected_fault",
                "detected_fault",
                "status",
                "latency_ms",
                "match",
            ],
        )
        writer.writeheader()
        writer.writerows(records)

    with open(JSON_OUT, "w") as f:
        json.dump(
            {
                "mode": "offline_corpus_verification",
                "total_cases": len(corpus_cases),
                "accuracy_pct": accuracy_pct,
                "results": records,
            },
            f,
            indent=2,
        )

    print(f"\n Dynamic HIL Corpus Accuracy: {accuracy_pct:.2f}%")
    print(
        " Artifacts saved:\n"
        f"  {CSV_OUT}\n"
        f"  {JSON_OUT}"
    )


def run_live_hil(port: str, baudrate: int = 115200):
    print(
        f" Initializing Hardware-in-the-Loop on live device "
        f"at {port} ({baudrate} baud)..."
    )

    monitor = FirmLensHILMonitor(
        port=port,
        baudrate=baudrate,
    )

    if not monitor.connect():
        print(f"[!] Failed to connect to serial port: {port}")
        return

    parser = CrashParser()

    monitor.start()

    # Allow the serial monitor to initialize and capture initial device output.
    time.sleep(2.0)

    payloads = [
        ("BENCH-001", b"GET / HTTP/1.1\r\n\r\n"),
        ("BENCH-002", b"A" * 64 + b"\n"),
        ("BENCH-003", b"A" * 256 + b"\n"),
        ("BENCH-004", b"%s%s%s%s%s%s%s%s\n"),
        ("BENCH-005", b"A" * 1024 + b"\n"),
    ]

    records = []

    for test_id, payload in payloads:
        t0 = time.perf_counter()

        if monitor.serial_conn and monitor.serial_conn.is_open:
            monitor.serial_conn.write(payload)
            monitor.serial_conn.flush()

        # Wait for the device/HIL monitor to observe a possible response,
        # panic, reset, or other fault condition.
        time.sleep(1.0)

        t1 = time.perf_counter()

        is_crashed = monitor.crash_detected.is_set()

        crash_log = list(monitor.crash_log)

        if is_crashed:
            crash_result = parser.parse_log(crash_log)
        else:
            crash_result = {
                "status": "Clean",
                "fault_type": "None",
            }

        detected_fault = crash_result.get(
            "fault_type",
            "None",
        )

        detected_status = crash_result.get(
            "status",
            "Clean",
        )

        # IMPORTANT:
        #
        # The live fuzz vectors currently do not have independently
        # established exact fault-type ground truth.
        #
        # Therefore this benchmark does NOT claim that a specific
        # vulnerability/fault type was correctly classified.
        #
        # Instead, "match" means that the HIL system actually observed
        # a non-clean fault condition for the vector.
        fault_detected = (
            detected_status != "Clean"
            and detected_fault not in ("None", "", None)
        )

        record = {
            "test_case_id": test_id,
            "test_name": f"Live Fuzz Vector {test_id}",
            "expected_fault": "Crash",
            "detected_fault": detected_fault,
            "status": detected_status,
            "latency_ms": round(
                (t1 - t0) * 1000,
                2,
            ),
            "match": fault_detected,
        }

        records.append(record)

        print(
            f" {test_id}: "
            f"Status={record['status']} | "
            f"Fault={record['detected_fault']} | "
            f"Detected={record['match']}"
        )

    monitor.stop()

    with open(CSV_OUT, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "test_case_id",
                "test_name",
                "expected_fault",
                "detected_fault",
                "status",
                "latency_ms",
                "match",
            ],
        )

        writer.writeheader()
        writer.writerows(records)

    detected_count = sum(
        1 for record in records
        if record["match"]
    )

    detection_rate = (
        detected_count / len(records) * 100
        if records
        else 0.0
    )

    # This is intentionally called detection_rate rather than
    # precision/recall/F1 because the current live vectors do not
    # provide independent clean/vulnerable ground-truth labels.
    summary = {
        "mode": "live_hil",
        "serial_port": port,
        "baudrate": baudrate,
        "total_cases": len(records),
        "faults_detected": detected_count,
        "fault_detection_rate_pct": round(
            detection_rate,
            2,
        ),
        "note": (
            "Live HIL vectors are reported as fault-detection "
            "observations. Exact fault-type accuracy, precision, "
            "recall, and F1 are not claimed because independent "
            "per-vector ground-truth labels are not established "
            "by the current live benchmark harness."
        ),
        "results": records,
    }

    with open(JSON_OUT, "w") as f:
        json.dump(
            summary,
            f,
            indent=2,
        )

    print(
        "\n Live HIL benchmark completed."
    )

    print(
        f" Fault detection: "
        f"{detected_count}/{len(records)} "
        f"({detection_rate:.2f}%)"
    )

    print(
        " Artifacts saved:\n"
        f"  {CSV_OUT}\n"
        f"  {JSON_OUT}"
    )


def main():
    target_port = (
        sys.argv[1]
        if len(sys.argv) > 1
        else find_default_port()
    )

    if target_port:
        run_live_hil(target_port)
    else:
        run_offline_corpus_evaluation()


if __name__ == "__main__":
    main()