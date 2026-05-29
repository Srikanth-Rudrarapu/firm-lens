# FirmLens: Cyber-Physical Systems & Embedded IoT Firmware Security Analysis Engine

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-darkgreen.svg)]()
[![Platform Support](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-blueviolet.svg)]()
[![Framework](https://img.shields.io/badge/Architecture-Espressif%20%7C%20STM32-orange.svg)]()

FirmLens is an industrial-grade security framework engineered for the automated forensic auditing and vulnerability mapping of firmware in cyber-physical systems (CPS) and embedded IoT devices. By bridging the gap between low-level hardware extraction and high-level static application security testing (SAST), FirmLens provides a unified pipeline for identifying supply-chain vulnerabilities, memory safety flaws, and architectural security gaps.
FirmLens enables compliance with international standards, including NIST SP 800-193 (Firmware Resiliency Guidelines) and ETSI EN 303 645 (IoT Security Standard).

# Framework Architecture
FirmLens utilizes a modular, decoupled architecture to ensure extensibility and strict data isolation across the analysis lifecycle.
Plaintext
FirmLens/
├── firm_lens/
│   ├── analyzers/    # Extensible heuristic SAST/SCA security modules
│   ├── extractor/    # Bare-metal UART/ROM bootloader interface layers
│   ├── reports/      # Multi-format telemetry & compliance engine
│   └── utils/        # Mathematical & forensic primitives
├── config/           # Declarative JSON schemas
├── data/             # Relational vulnerability knowledge base
└── pyproject.toml    # PEP 517 build distribution manifesto

# Key Engineering Capabilities
Hardware-Level Ingestion: Automated bare-metal extraction from Espressif (ESP32) and ARM Cortex (STM32) silicon.
Heuristic Analysis Suite: Parallelized scanning engine including entropy mapping, symbolic backdoor identification, and memory sink auditing.
Supply-Chain Intelligence: Automated CVE/CWE correlation via local vulnerability databases.
Enterprise Reporting: Dual-mode output for CI/CD integration (JSON) and forensic audits (Interactive HTML).

# Getting Started 
Installation
Bash
git clone https://github.com/your-username/FirmLens.git
cd FirmLens
python3 -m venv venv && source venv/bin/activate
pip install -e .
Usage
1. Extract Firmware from Hardware:
Bash
firm-lens extract --chip esp32 --output ./firmware.bin
2. Perform Deep Security Assessment:
Bash
firm-lens analyze ./firmware.bin --format all
🛡️ Security Methodology
FirmLens adopts a Data-Driven Heuristic Framework. Unlike traditional rigid security scanners, FirmLens decouples analysis logic from intelligence definitions.
Dynamic Correlation: Intelligence mappings (CISA KEV, EPSS scores) are decoupled from the core analyzer logic, allowing the engine to evolve against the current threat landscape without requiring source code modifications.
Actionable Remediation: Every finding is accompanied by an Actionable Engineering Remediation Blueprint, providing engineers with concrete steps to harden their implementation against specific CWE-identified flaws.
📜 Regulatory Compliance & Intelligence
FirmLens is designed to assist organizations in meeting modern cybersecurity mandates:
NIST SP 800-213: Secure Device Boot Strapping & Data Protection Baselines.
ETSI EN 303 645: Non-hardcoded credential enforcement & secure communication interfaces.
⚖️ Licensing
Distributed under the MIT License. See LICENSE for more information.




# FirmLens: Industrial-Grade Cyber-Physical Systems & Embedded IoT Firmware Security Analysis Engine

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-darkgreen.svg)]()
[![Platform Support](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-blueviolet.svg)]()
[![Framework](https://img.shields.io/badge/Architecture-Espressif%20%7C%20STM32-orange.svg)]()

FirmLens is an advanced, automated static application security testing (SAST) and bare-metal hardware-level extraction framework architected for the forensic auditing, validation, and vulnerability mapping of cyber-physical systems (CPS) and deeply embedded Internet of Things (IoT) firmware images. 

The engine automates hardware-level bootloader carving, sliding-window Shannon entropy mapping, algorithmic cryptographic boundary tracking, symbolic backdoor identification, and automated Common Weakness Enumeration (CWE) and Common Vulnerabilities and Exposures (CVE) supply-chain correlation. Designed for high-reliability mission-critical infrastructure validation, FirmLens ensures compliance with leading international cybersecurity standards, including **NIST SP 800-193 (Firmware Resiliency Guidelines)** and **ETSI EN 303 645**.

---

## 🏛 Framework Architecture & Design Schema

FirmLens implements a modular, decoupled pipeline architecture engineered for extreme performance and strict data isolation across execution scopes. Below is the technical directory map of the distributed ecosystem:

```text
FirmLens/
├── firm_lens/
│   ├── __init__.py
│   ├── main.py                       # Core CLI Orchestrator & Multi-Command Gateway
│   ├── banner.py                     # Package Monospaced ANSI Initialization Branding
│   │
│   ├── analyzers/                    # Synchronous Behavioral SCA/SAST Suite
│   │   ├── __init__.py
│   │   ├── app_string_analyzer.py    # Extracts high-entropy application layers & tokens
│   │   ├── backdoor_analyzer.py      # Isolates bypass logic gates & hidden debug URIs
│   │   ├── crypto_analyzer.py        # Validates block cipher structures and identifies weak hashing
│   │   ├── cve_analyzer.py           # Maps build components to live National Vulnerability Databases
│   │   ├── dangerous_function_analyzer.py # Audits memory stack vectors for unconstrained print sinks
│   │   ├── esp32_partition_analyzer.py # Validates partition boundaries & unencrypted NVS markers
│   │   ├── flash_encryption_analyzer.py # Implements sliding-window Shannon entropy distribution sweeps
│   │   ├── insecure_endpoint_analyzer.py # Discovers cleartext network routes (MQTT/HTTP/WS)
│   │   ├── secrets_analyzer.py       # Scans binary segments for hardcoded PEM/asymmetric private keys
│   │   ├── secure_boot_analyzer.py   # Validates physical signature headers and magic markers
│   │   └── weak_xor_analyzer.py      # Detects primitive mask obfuscation table arrays
│   │
│   ├── extractor/                    # Bare-Metal Silicon Hardware Interface Layers
│   │   ├── __init__.py
│   │   ├── esp32_extractor.py        # Communicates with Espressif ROM Download bootloaders
│   │   └── stm32_extractor.py        # Handles memory space mapping for ARM Cortex storage layers
│   │
│   ├── reports/                      # Enterprise Telemetry & Compliance Output Pipeline
│   │   ├── __init__.py
│   │   ├── html_report.py            # Compiles dynamic web dashboards with expandable remediation drawers
│   │   ├── json_report.py            # Generates structured, machine-readable CI/CD data payloads
│   │   └── report_generator.py       # Dual-mode compliance passport compiler engine
│   │
│   └── utils/                        # Low-Level Forensic and Mathematical Utilities
│       ├── __init__.py
│       ├── binary_utils.py           # Manages raw stream sliding offsets and byte slice alignments
│       ├── cwe_mapping.py            # Maps algorithmic indicators directly to MITRE CWE taxonomies
│       ├── esp32_utils.py            # Resolves sector map flags and chip partition headers
│       ├── file_type.py              # Magic-byte identification engine for unidentified blobs
│       ├── findings.py               # Data class defining standardized vulnerability attributes
│       ├── string_extractor.py       # Customized, performance-tuned ASCII/Unicode string extraction loop
│       └── zip_firmware_extractor.py # Unpacks archived OTA compressed firmware components
│
├── samples/                          # Reference binary test vector configurations
├── pyproject.toml                    # Standard PEP 517 build distribution manifesto
└── README.md                         # Framework technical documentation exhibit
🛠 Low-Level Operational Pipeline Under the Hood
FirmLens operates across three primary stages, executing sequential, high-fidelity operations to ensure a comprehensive security audit:

[ Connected ESP32/STM32 Device ]
                │
                ▼ (Stage 1: Bare-Metal Extraction Via UART Sync)
     [ firm-lens extract ]
                │
                ▼ (Generates Raw Unified Flash Binary *.bin)
     [ firm-lens analyze ]
                │
                ├─▶ Flash Encryption Module (Sliding-Window Shannon Entropy Evaluation)
                ├─▶ Secure Boot Auditor (Asymmetric Signature Block Verification)
                ├─▶ Secrets Discovery Loop (Regex-based Private Key Scanning)
                ├─▶ Memory Safety Checker (Unbounded Buffer & Format String Sink Isolation)
                │
                ▼ (Stage 3: Enterprise Telemetry & Compliance Passports)
[ HTML Dashboard UI / JSON Data Payloads for Corporate CI/CD Pipelines ]
1. Bare-Metal Ingestion & Auto-Discovery

Using the extraction pipeline, FirmLens interfaces directly with the hardware silicon's ROM Bootloader via serial UART buses. The framework asserts virtual DTR (Data Terminal Ready) and RTS (Request to Send) control lines to toggle the physical reset transistor matrix, forcing the MCU into its download state. It reads the internal SPI configuration parameters to carves the entire flash footprint sequentially.

2. Multi-Tiered Static Vulnerability Analysis

Once a local or dumped firmware binary is loaded, it is passed through 11 independent, parallelized analysis submodules:

Shannon Entropy Analysis: Computes local byte densities across moving windows to isolate plaintext application space from encrypted or compressed partitions, calculating density tracking curves (Expected>60.00%).

Memory Safety & Format String Auditing: Analyzes compiled binary blocks to identify unconstrained user-controlled input paths terminating inside formatting sinks (e.g., matching hex signatures of vulnerable sprintf or printf routines), tracking to CWE-134 and CWE-120.

Cryptographic Boundary Audits: Targets weak primitives, fixed XOR obfuscation grids, and broken hashing algorithms like MD5 (CWE-327 / CWE-328).

3. Compliance & Verification Reporting

Findings are compiled into machine-readable JSON formats for enterprise DevSecOps build chains and an advanced web UI report. To avoid false alarms, the report implements Dual-Mode Logic: actual vulnerabilities trigger code-level Actionable Engineering Remediation Blueprints, while successful diagnostic checks render as green Security Verification Passports, establishing audit documentation for regulatory compliance reviews.

🚀 Installation & Environment Setup
System Prerequisites

Ensure your local development environment meets the following baseline operating system dependencies:

Python: Runtime environment versions 3.10, 3.11, or 3.12.

Operating Systems: macOS Ventura or higher, Ubuntu Linux 22.04 LTS or higher, or Windows 11 (PowerShell terminal).

Hardware Drivers: For direct device extractions, ensure the host system has physical USB-to-Serial bridge drivers installed (e.g., Silicon Labs CP210x, FTDI, or CH340).

From-Source Installation Sequence

Clone the core project ecosystem repository and establish an isolated virtual python environment space:

Bash
# Clone the repository framework
git clone [https://github.com/your-username/FirmLens.git](https://github.com/your-username/FirmLens.git)
cd FirmLens

# Establish a localized Python virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate

# Install the package securely in developer editable mode
pip install --upgrade pip
pip install firm-lens
⌨️ Command Line Interface (CLI) Production Manual
FirmLens implements a highly communicative, modern CLI engineered using the Click and Rich presentation runtimes.

To explore the top-level capabilities parameters, execute:

Bash
firm-lens --help
1. firm-lens categories

Lists all active heuristic software and hardware analysis domains integrated into the scanner subsystem engine.

Bash
firm-lens categories
2. firm-lens extract

Automates real-time raw firmware image carving out of physically connected microcontroller chips.

Bash
# Invoke the interactive GUI auto-wizard assistant 
firm-lens extract

# Command Line Option Mode Pass (Explicit parameters)
firm-lens extract --chip esp32 --live-port /dev/cu.usbserial-0001 --baud 460800 --output ~/Downloads/target_dump.bin
Key Feature Parameters:

Smart Auto-Discovery Fallback: If the --live-port flag is omitted, FirmLens scans the system's USB bus layers natively using pyserial. If a single USB-to-Serial bridge profile is found, it automatically mounts it and starts the process.

Dynamic Localized Downloads Routing: If the --output / -o flag is omitted, the framework automatically maps the user account's home profile to write the data payload cleanly to ~/Downloads/hardware_extracted_flash.bin to maintain global pipeline execution safety across host environments.

Live Progress Tracking: Utilizes unbuffered background threads to intercept stream byte blocks, updating a visual progress bar indicating exact execution status.

3. firm-lens analyze

Executes deep static application auditing loops against target firmware binaries.
firm-lens analyze ~/Downloads/hardware_extracted_flash.bin --format all

Supported Output Format Modifiers:

--format terminal: Generates a high-contrast enterprise scoreboard panel directly within your terminal view, breaking down threat profiles across Critical, High, Medium, and Advisory bands.

--format html: Generates a premium UI dashboard containing interactive JavaScript sorting toggles and expandable remediation drawers.

--format json: Outputs a clean machine-readable payload designed for native ingestion by centralized SIEM platforms or corporate CI/CD code compliance gates.

--format all: Simultaneously compiles every reporting variant.

4. firm-lens init-db

Synchronizes the local vulnerability indexing engines with updated signature tracking definition arrays.
firm-lens init-db

