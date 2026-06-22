# FirmLens

**Industrial-Grade Embedded IoT Firmware Security Analysis Engine**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/Python-3.10%2B-darkgreen.svg)]()
[![Platform Support](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-blueviolet.svg)]()
[![Architecture](https://img.shields.io/badge/Architecture-Espressif%20SoCs-orange.svg)]()

FirmLens is a comprehensive security analysis framework engineered specifically for embedded IoT device firmware, with deep-level heuristics optimized for Espressif SoC architectures (ESP32, S2, S3, C3). 

The framework bridges the gap between static binary analysis and live dynamic hardware testing by automating partition carving, Shannon entropy mapping, symbolic vulnerability tracking, and Hardware-in-the-Loop (HIL) fuzzing into a single analytical pipeline. It ensures compliance with leading international cybersecurity standards, including **NIST SP 800-213** and **ETSI EN 303 645**.

---

## System Architecture & Data Flow

FirmLens utilizes a multi-stage ingestion and correlation pipeline to process raw binaries and map them against live threat intelligence.

![System Architecture](https://raw.githubusercontent.com/Srikanth-Rudrarapu/firm-lens/main/assets/architecture.png)

---

## Installation

FirmLens requires Python 3.10+ and relies on the Espressif `esptool` for physical hardware interactions.

### Option 1: Install via PyPI (Stable Release)
The recommended installation method for production environments.

```bash
pip install firm-lens
```

### Option 2: Install from Source (Bleeding Edge)
For security researchers who want the latest dynamic intelligence feeds and hardware fuzzing updates directly from the repository.

```bash
git clone https://github.com/Srikanth-Rudrarapu/firm-lens
cd firm-lens
pip install -e .
```

*Note on Hardware Drivers: For direct physical extraction and dynamic HIL fuzzing, ensure your host operating system has the appropriate USB-to-Serial bridge drivers installed (e.g., CP210x, FTDI).*

---

## Basic commands after installation

```bash
firm-lens
firm-lens --help
firm-lens --version
```

---

## Initial Setup

Before executing the first pipeline scan, initialize the local relational threat intelligence database. This securely fetches and synchronizes the latest CISA KEV catalogs, EPSS probability scores, and CVE mapping arrays locally.

```bash
firm-lens init-db
```

---

## Operational Usage

FirmLens is executed via a centralized Command Line Interface (CLI).

### 1. Static Deep Analysis
Executes deep static application auditing loops against target firmware binaries.

```bash
firm-lens analyze /path/to/target_firmware.bin -f all
```

**Output Routing (`-o` flag):**
* **Default Behavior:** If the `-o` flag is omitted, FirmLens safely isolates artifacts to `~/Downloads/FirmLens_Reports/Static/`.
* **Explicit Output:** You may specify a custom directory or exact filename using the `-o` flag:
  `firm-lens analyze /path/to/firmware.bin -o /custom/path/my_report -f all`

### 2. Hardware Firmware Extraction
Automates real-time raw firmware image carving directly from a physically connected microcontroller chip over UART.

#### Physical Interconnect Configuration
![ESP32 Hardware Extraction Setup](https://raw.githubusercontent.com/Srikanth-Rudrarapu/firm-lens/main/assets/esp32-device.png)

#### Completed Extraction TTY Output Stream
![ESP32 Extraction CLI Stream](https://raw.githubusercontent.com/Srikanth-Rudrarapu/firm-lens/main/assets/esp32-extraction.png)

```bash
firm-lens extract --live-port /dev/cu.usbserial-0001 --chip esp32 --baud 115200
or 
firm-lens extract
```
* **Auto-Discovery:** If `--live-port`, `--chip esp32` and `--baud 115200` is omitted, the engine utilizes native PySerial routines to identify and mount the active USB bridge automatically.
* **Output Routing:** Automatically writes the target payload to `~/Downloads/hardware_extracted_flash_[TIMESTAMP].bin` unless explicitly overridden via the `-o` flag.

### 3. Dynamic Hardware-in-the-Loop (HIL) Fuzzing
Executes live serial or network fuzzing against a connected device to test memory execution boundaries and capture hardware faults in real-time.

```bash
# Serial UART Fuzzing
firm-lens dynamic -f all

# Network Boundary Fuzzing
firm-lens dynamic --target-ip 192.168.1.150 -f all
```

**Output Routing (`-o` flag):**
* **Default Behavior:** Dynamic audit artifacts are routed separately to `~/Downloads/FirmLens_Reports/Dynamic/` to maintain data isolation from static scans.
* **Explicit Output:** You may specify a custom directory or exact filename using the `-o` flag:
  `firm-lens dynamic --target-ip 192.168.1.150 -o /custom/path/my_dynamic_report -f all`

### 4. Component Discovery
List all active heuristic software analyzers and hardware target domains currently loaded into the scanner subsystem.

```bash
firm-lens categories
```

---

## Enterprise Reporting & Output Formats

FirmLens provides high-fidelity reporting designed for enterprise security teams and CI/CD pipelines. Modifiers are passed via the `-f` or `--format` flag:

* **Terminal (Default):** Live execution tracking, offset mapping, and color-coded scoreboards printed directly to `stdout`.
* **HTML (`-f html`):** Generates a client-side web dashboard containing interactive metrics, vulnerability offset tracking, and expandable engineering remediation blueprints.
* **JSON (`-f json`):** Outputs a clean, machine-readable payload designed for native ingestion by SIEM platforms and automated compliance gates.
* **Combined (`-f all`):** Compiles both the HTML and JSON file artifacts simultaneously.

---
### Static Engine Reports
### A. Terminal Execution Scoreboard
![FirmLens CLI Output](https://raw.githubusercontent.com/Srikanth-Rudrarapu/firm-lens/main/assets/cli-report.png)
![FirmLens CLI Output](https://raw.githubusercontent.com/Srikanth-Rudrarapu/firm-lens/main/assets/cli-report1.png)

### B. Interactive HTML Dashboard
![FirmLens HTML Report](https://raw.githubusercontent.com/Srikanth-Rudrarapu/firm-lens/main/assets/html-report.png)
![FirmLens HTML Report](https://raw.githubusercontent.com/Srikanth-Rudrarapu/firm-lens/main/assets/html-report1.png)

### C. CI/CD JSON Payload (SIEM Integration)
```json
{
    "schema_version": "1.0.0",
    "scan_metadata": {
        "tool": "FirmLens",
        "target_asset": "hardware_extracted_flash.bin",
        "timestamp": "2026-06-22T13:11:39.602468",
        "telemetry_audit_vectors_enforced": 10,
        "total_security_anomalies_isolated": 12,
        "severity_distribution_scoreboard": {
            "Critical": 1,
            "High": 5,
            "Medium": 3,
            "Low": 1,
            "Info": 2
        }
    },
    "findings": [
        {
            "compliance_control_domain": "Static Cryptographic Key & Credential Escrow Checks",
            "id": "FL-CRED-STRUCT",
            "severity": "Critical",
            "title": "Hardcoded Wi-Fi Config Struct Detected",
            "cwes": [
                "CWE-798",
                "CWE-259"
            ],
            "is_vulnerability": true,
            "evidence": [
                "[0xa524] Memory Block -> SSID: 'OfficeNet' | PSK: 'Passw0rd123!",
                "[0xc244] Memory Block -> SSID: 'OfficeNet' | PSK: 'Passw0rd123!",
                "[0xc2d0] Memory Block -> SSID: 'HomeNetwork' | PSK: 'SuperSecret123"
            ],
            "offsets": [
                "0xa524, 0xc244, 0xc2d0"
            ],
            "scope": "local",
            "remediation_blueprint": "Purge raw credential values, private keys, and API tokens from code strings. Migrate secret data into an independent, encrypted NVS partition block or handle configuration handshakes dynamically using runtime encrypted key exchanges. The exposed structures are located at offset(s): 0xa524, 0xc244, 0xc2d0.",
            "threat_intelligence_telemetry": {
                "active_exploitation": "active",
                "epss_score": 0.874,
                "nist_sp_800_213": "NIST SP 800-213 Data Protection Baseline",
                "etsi_en_303_645": "ETSI EN 303 645 Compliance Rule 5.1-1 (No Hardcoded Credentials)"
            }
        }
    ]
}
```

---

### Dynamic Engine Reports
### A. Terminal Execution Scoreboard
![FirmLens CLI Output](https://raw.githubusercontent.com/Srikanth-Rudrarapu/firm-lens/main/assets/dynamic-cli.png)

### B. Interactive HTML Dashboard
![FirmLens HTML Report](https://raw.githubusercontent.com/Srikanth-Rudrarapu/firm-lens/main/assets/dynamic-html.png)

### C. CI/CD JSON Payload (SIEM Integration)
```json
{
    "schema_version": "1.0.0",
    "scan_metadata": {
        "tool": "FirmLens",
        "target_asset": "Live ESP32 Target (UART Interconnect)",
        "timestamp": "2026-06-22T18:08:56.359994",
        "telemetry_audit_vectors_enforced": 1,
        "total_security_anomalies_isolated": 1,
        "severity_distribution_scoreboard": {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 1
        }
    },
    "findings": [
        {
            "compliance_control_domain": "Physical Hardware Device Fuzzing & Interaction",
            "id": "FL-HITL-001",
            "severity": "Info",
            "title": "Hardware-in-the-Loop Fuzzing Boundary Verified",
            "cwes": [],
            "is_vulnerability": false,
            "evidence": [
                "Dynamic Telemetry Validation: Microcontroller unit smoothly processed input queues without raising runtime register exceptions, memory boundary spikes, or kernel loops."
            ],
            "offsets": [
                "System Metric Boundary"
            ],
            "scope": "global",
            "remediation_blueprint": "Verification Metric: Continuous testing pipeline milestone achieved. No runtime memory corruption or state engine desynchronization isolated during this execution window.",
            "threat_intelligence_telemetry": {
                "active_exploitation": "unsupported",
                "epss_score": null,
                "nist_sp_800_213": "NIST SP 800-213 Data Protection Baseline",
                "etsi_en_303_645": "ETSI EN 303 645 Standard Audit Baseline"
            }
        }
    ]
}
```

---

## License
Distributed under the MIT License. See `LICENSE` for more information.

## Disclaimer
FirmLens is engineered strictly for authorized security research, compliance auditing, and defensive engineering. Ensure explicit legal authorization is granted prior to analyzing or interacting with target hardware.

## Support the Project
If you found FirmLens useful for your security research or compliance auditing, please consider giving the repository a ⭐ on GitHub. It helps the project gain visibility and supports ongoing open-source development.


[![GitHub stars](https://img.shields.io/github/stars/Srikanth-Rudrarapu/firm-lens.svg?style=social&label=Star)](https://github.com/Srikanth-Rudrarapu/firm-lens)