# FirmLens

**Industrial-Grade Embedded IoT Firmware Security Analysis Engine**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/Python-3.10%2B-darkgreen.svg)]()
[![Platform Support](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-blueviolet.svg)]()
[![Architecture](https://img.shields.io/badge/Architecture-Espressif%20SoCs-orange.svg)]()

## Why FirmLens? The Genesis

Embedded firmware security tooling is often fragmented across:
- generic binary analysis tools
- emulation-based frameworks
- vendor-specific debugging utilities

While powerful in isolation, these approaches often lack deep awareness of ESP32 firmware structures such as partition tables, bootloader metadata, and ESP-IDF-specific layouts.

FirmLens was designed to address this gap by providing a focused analysis framework for ESP32-class firmware, combining static inspection with optional hardware-assisted workflows.

It provides an integrated approach that:

1. **Parses ESP32 firmware structures** including partition tables, NVS regions, and bootloader metadata without requiring full-system emulation.
2. **Correlates static findings with external vulnerability intelligence sources**, including CISA KEV and EPSS, where matches are available, to enrich vulnerability context beyond traditional CVSS scoring.
3. **Supports Hardware-in-the-Loop (HIL) testing workflows**, enabling controlled input-based testing of connected devices in laboratory environments.

Beyond static analysis, the framework includes mechanisms to detect fault conditions during hardware interaction testing, such as reboot loops, exception traces, and memory corruption indicators. These outputs are mapped to CWE categories to support structured vulnerability reporting.

FirmLens is intended as a **research-grade embedded security analysis framework**, initially optimized for Espressif SoCs (ESP32, ESP32-S2/S3, ESP32-C3), with a modular architecture designed for future extension to other embedded platforms.

It is designed to support embedded security research workflows aligned with industry practices such as **NIST SP 800-213** and **ETSI EN 303 645**, where applicable.

### Scope

It is strictly intended for authorized security research, firmware analysis, and defensive testing in controlled environments.

---

## System Architecture & Data Flow

FirmLens uses a multi-stage firmware analysis pipeline designed for ESP32-class devices to process raw firmware binaries and extract structured security-relevant artifacts.

The pipeline performs:
- firmware partition discovery and parsing
- entropy-based binary structure mapping
- static string and configuration analysis
- optional correlation with external vulnerability intelligence sources such as CISA KEV and EPSS, where applicable

The output of each stage is normalized into structured reports (JSON/HTML) for downstream analysis, reporting, or integration into security workflows.

The system is optimized for Espressif ESP32-family firmware but is designed with a modular architecture that allows future extension to additional embedded architectures.

![System Architecture](https://raw.githubusercontent.com/Srikanth-Rudrarapu/firm-lens/main/assets/architecture.png)

---

## Comparative Analysis and Project Scope

The following comparison is provided for context, not as a claim of superiority over established tools. The IEEE manuscript contains a condensed version of this table due to formatting constraints, but the detailed architectural differences are outlined below:

| Feature | **FirmLens** | Binwalk | Firmadyne | EMBA |
| :--- | :--- | :--- | :--- | :--- |
| **Primary Focus** | Bare-metal ESP32 / RTOS security analysis | Generic binary extraction & signature matching | Full-system Linux firmware emulation | Embedded Linux filesystem security scanner |
| **Bare-Metal Partition Parsing** | Semantic decoding (NVS, OTA, boot boundaries) | Magic-byte signature carving only | N/A (Requires POSIX structure) | N/A (Requires unpacked rootfs) |
| **Dynamic Triage (UART/HIL)** | Physical UART crash & register panic parsing | Static file analysis only | Software emulation only | Static file analysis only |
| **Hardware Boot Crypto Checks** | Validates RSA Secure Boot V2 & Flash Encryption | None | None | General Linux crypto config checks |
| **Threat Intel Correlation** | Direct mapping to FIRST EPSS & CISA KEV | None | Dynamic network exploit validation | Vulners/NVD CVE matching |
| **CI/CD & Performance** | Sub-second static scans with JSON/HTML reports | Fast execution with CLI/API output | Heavy software emulation overhead | Resource-intensive multi-engine scans |

**Clarification**: Binwalk is a widely-used, mature extraction tool that has added ESP32 signatures. FirmLens does not replace Binwalk—rather, it complements it by providing **semantic, Espressif-specific security analysis** that Binwalk does not attempt. Firmadyne targets Linux-based firmware and is not designed for ESP32's FreeRTOS environment. EMBA is a comprehensive multi-engine scanner for Linux root filesystems, but it cannot directly analyze monolithic bare-metal flash blobs compiled for Xtensa or RISC-V architectures without target-specific support.

FirmLens occupies a distinct niche: **architectural semantic analysis for Espressif SoCs**, combining static binary inspection, physical hardware evaluation, and threat intelligence into a unified pipeline.

---

## Installation

FirmLens requires Python 3.10+ and relies on the Espressif `esptool` for physical hardware interactions.

### Option 1: Install via PyPI (Stable Release)
The recommended installation method for production environments.

```bash
#Install
pip install firm-lens

#Upgrade
pip install --upgrade firm-lens
```

### Option 2: Install from Source (Bleeding Edge)
For security researchers who want the latest dynamic intelligence feeds, or for academic peer reviewers intending to run the replication suite and generate evaluation figures.

```bash
git clone https://github.com/Srikanth-Rudrarapu/firm-lens
cd firm-lens
pip install -e .[dev]
```
*(Note: The `[dev]` flag installs the additional plotting and benchmarking libraries required to run the `experiments/` replication suite).*

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
* **Auto-Discovery:** If `--live-port`, `--chip` and `--baud` is omitted, the engine utilizes native PySerial routines to identify and mount the active USB bridge automatically.
* **Output Routing:** Automatically writes the target payload to `~/Downloads/hardware_extracted_flash_[TIMESTAMP].bin` unless explicitly overridden via the `-o` flag.

### 3. Dynamic Hardware-in-the-Loop (HIL) Fuzzing
Executes live serial or network fuzzing against a connected device to test memory execution boundaries and capture hardware faults in real-time.

* **Serial Payloads:** Injects boundary‑crossing strings (10‑byte, 32‑byte, 100‑byte, and 1000‑byte overflow buffers) plus format string primitives (%x %x %s %n) to exercise boundary conditions associated with buffer overflow and format string weaknesses.
* **Network Payloads:** Sends oversized HTTP URIs, HTTP header format string injections, and raw TCP junk floods to the target’s TCP stack (port 80 by default).
* **Crash Correlation:** The serial_monitor continuously scans for Guru Meditation Errors, EXCCAUSE hardware exceptions, abrupt reboots (SW_CPU_RESET), and 414141 (ASCII overflow) memory patterns. Upon detection, the crash_parser maps the fault to CWE-120 (Buffer Overflow) or CWE-134 (Format String) and extracts the corrupted instruction pointer (EPC1).

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
                "[0xa524] Memory Block -> SSID: 'TestSSID' | PSK: 'TESTPASSWORD123",
                "[0xc244] Memory Block -> SSID: 'ExampleSSID' | PSK: 'ExamplePassword",
                "[0xc2d0] Memory Block -> SSID: 'DemoNetwork' | PSK: 'DemoPassword123"
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

## Versioning

FirmLens follows Semantic Versioning (SemVer).

- Major versions introduce significant architectural changes.
- Minor versions introduce new capabilities and analysis modules.
- Patch versions contain fixes, documentation improvements, and maintenance updates.

## Citation

FirmLens is an open-source firmware security analysis framework. If you use FirmLens in research, publications, technical reports, or security assessments, please cite the software artifact:

```bibtex
@software{firmlens_software,
  author    = {Rudrarapu, Srikanth},
  title     = {FirmLens: Industrial-Grade Embedded IoT Firmware Security Analysis Engine},
  year      = {2026},
  version   = {1.0.4},
  url       = {https://github.com/Srikanth-Rudrarapu/firm-lens}
}
```

> *An empirical evaluation manuscript describing FirmLens is in preparation. For the latest publication status and citation (preprint/DOI, once available), see [CITATION.cff](https://github.com/Srikanth-Rudrarapu/firm-lens/blob/main/CITATION.cff) or [CITATION.bib](https://github.com/Srikanth-Rudrarapu/firm-lens/blob/main/CITATION.bib), which are kept current independent of software releases.*

## Support the Project

If you found FirmLens useful for your security research or compliance auditing, consider giving the repository a star on GitHub. It helps the project gain visibility and supports ongoing open-source development.

[![GitHub stars](https://img.shields.io/github/stars/Srikanth-Rudrarapu/firm-lens.svg?style=social&label=Stars)](https://github.com/Srikanth-Rudrarapu/firm-lens)

## Disclaimer

FirmLens is engineered strictly for authorized security research, compliance auditing, and defensive engineering. Ensure explicit legal authorization is granted prior to analyzing or interacting with target hardware.  

## License

Distributed under the MIT License. See `LICENSE` for more information.  