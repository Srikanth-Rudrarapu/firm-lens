FirmLens — Firmware Extraction & Security Analysis Toolkit
FirmLens is an open‑source toolkit for analyzing embedded firmware images (ESP32, STM32, ZIP‑based OTA bundles, and generic .bin/.img/.hex files).
It performs secure boot checks, flash encryption analysis, weak crypto detection, and hardcoded secrets scanning — all from a simple CLI.
Designed for AppSec engineers, IoT researchers, and firmware security auditors.

🚀 Features
🔍 Firmware Analysis
• Secure Boot heuristics (ESP32)
• Flash encryption entropy analysis
• Weak crypto signature detection (MD5, SHA1, DES, RC4, AES‑ECB)
• Hardcoded secrets scanning (API keys, private keys, passwords)
• ZIP firmware bundle extraction with strict safety limits

🧩 Extraction Support
• ESP32 firmware metadata extraction
• STM32 vector table extraction
• Safe ZIP extraction (no nested ZIPs, size limits, file count limits)

CLI Tool
firm-lens analyze firmware.bin
firm-lens extract firmware.bin --chip esp32

🛡️ Security‑First Design
• No code execution
• No writes to firmware
• No network calls
• Safe ZIP extraction
• Analyzer failures never crash the tool

🖥️ Usage

Analyze a firmware image
firm-lens analyze samples/sample_firmware.bin

Extract ESP32 firmware metadata
firm-lens extract firmware.bin --chip esp32

Extract STM32 firmware metadata
firm-lens extract firmware.bin --chip stm32

Analyze a ZIP firmware bundle
firm-lens analyze update_package.zip

📊 Example Output
┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ Analyzer              ┃ ID               ┃ Severity ┃ Title                        ┃ CWEs         ┃
┡━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ CryptoAnalyzer        │ FIRM-CRYPTO-001  │ High     │ SHA1 Hash Detected           │ CWE-327      │
│ SecretsAnalyzer       │ FIRM-SECRET-001  │ Critical │ Detected Private Key         │ CWE-798,321  │
│ FlashEncryptionAnaly… │ FIRM-FLASH-001   │ High     │ Firmware appears unencrypted │ CWE-311      │
│ SecureBootAnalyzer    │ FIRM-SECBOOT-002 │ Info     │ ESP32 headers valid          │ -            │
└───────────────────────┴──────────────────┴──────────┴──────────────────────────────┴──────────────┘
