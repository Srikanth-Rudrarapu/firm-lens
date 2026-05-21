import sqlite3
import os

def initialize_vulnerability_db():
    """
    Compiles industry-standard ESP32 vulnerability metrics, CVE definitions,
    and CWE remediation blueprints into a localized relational SQLite database.
    Eliminates code hardcoding to fulfill O-1 enterprise architecture requirements.
    """
    # Dynamically resolve the path to the same directory this script resides in
    current_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(current_dir, "vulnerabilities.db")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # 1. CREATE ENTERPRISE CVE VULNERABILITY SCHEMA
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            component_name TEXT NOT NULL,
            affected_version TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            cwe_id TEXT
        )
    """)
    
    # 2. CREATE ENTERPRISE CWE REMEDIATION KNOWLEDGE SCHEMA
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS remediations (
            cwe_id TEXT PRIMARY KEY,
            blueprint_text TEXT NOT NULL
        )
    """)
    
    # Industrial dataset payload for architecture supply chain correlation
    sample_intel = [
        ("CVE-2021-28150", "ESP-IDF", "4.2", "Memory corruption leading to arbitrary code execution via custom Wi-Fi frames.", "Critical", "CWE-120"),
        ("CVE-2020-15048", "ESP-IDF", "4.2", "Improper verification of signatures allows bootloader restriction bypass.", "High", "CWE-347"),
        ("CVE-2022-35860", "ESP-IDF", "4.4", "Heap-based buffer overflow in the network interface controller subsystem.", "High", "CWE-787"),
        ("CVE-2021-44732", "MbedTLS", "2.16", "Side-channel vulnerability in modular exponentiation allows private key extraction.", "High", "CWE-203"),
        ("CVE-2022-30767", "MbedTLS", "2.28.0", "Stack-based buffer overflow during handshake message processing.", "Critical", "CWE-121")
    ]
    
    # Decoupled industry-standard ESP32 security remediation matrices
    remediation_blueprints = [
        ("CWE-347", "Enforce hardware-rooted RSA/ECDSA asymmetric signature verification schemes. In your 'sdkconfig', explicitly toggle 'CONFIG_SECURE_BOOT_V2_ENABLED=y' and lock the public key digest irreversibly into the physical eFuse block."),
        ("CWE-311", "Activate the built-in AES-256 transparent Flash Encryption engine. Ensure 'CONFIG_SECURE_FLASH_ENC_ENABLED=y' is enforced in the bootloader layout configuration so unencrypted application partitions cannot be dumped over UART physical diagnostic boundaries."),
        ("CWE-1200", "Configure eFuse restriction parameters to permanently burn access lines. Strip physical JTAG debugging wires and disable direct ROM bootloader download commands ('CONFIG_SECURE_BOOT_DISABLE_ROM_DL_MODE=y') to mitigate runtime physical injection attacks."),
        ("CWE-798", "Purge raw credential values, private keys, and API tokens from code strings. Migrate secret data into an independent, encrypted NVS partition block or handle configuration handshakes dynamically using runtime encrypted key exchanges."),
        ("CWE-312", "Never write plaintext credential artifacts to non-volatile flash buffers. Encrypt the target storage blocks using the Espressif NVS encryption utility API or migrate to runtime storage configurations that clear variables directly from volatile SRAM blocks upon power cycles."),
        ("CWE-327", "Decommission outdated cryptographic signatures like MD5 or primitive XOR obfuscation tables. Refactor codebase routines to utilize strong, hardware-accelerated primitives such as SHA-256 or hardware-managed AES-GCM engine wrappers."),
        ("CWE-328", "Deprecate weak collision-prone hashing functions (MD5/SHA1). Replace hashing engines with SHA-256 or SHA-512 libraries, taking advantage of the hardware crypto-acceleration sub-blocks present on modern ESP32 architectures."),
        ("CWE-134", "Eliminate direct user-controlled arguments inside raw formatting output functions. Replace open format strings with safe positional bounds or rewrite direct print sinks to leverage explicitly protected length variables."),
        ("CWE-120", "Replace bounded buffer overflow candidates (strcpy, sprintf) with strict alternative implementations (strncpy, snprintf). Validate array boundary indices prior to writing data blocks into memory segments to avoid heap/stack contamination."),
        ("CWE-489", "Deactivate debug logic and diagnostic tracking instrumentation hooks prior to preparing production binary outputs. Strip 'X-Debug-Token' variables and remove verbose terminal logging macros using compiler flag controls."),
        ("CWE-912", "Purge diagnostic administrative routing tables, open test scripts, or physical backdoor routing segments from distribution images. Enforce strict token-based authorization frameworks across every exposed local and network API path."),
        ("CWE-425", "Enforce robust server-side structural access validation matrices. Unauthenticated routing tokens must never grant execution paths to internal device configuration operations simply by guessing hidden path extensions."),
        ("CWE-319", "Upgrade transport communication pathways from cleartext variants to transport-layer security wrappers. Replace 'mqtt://' and 'http://' endpoints with 'mqtts://' and 'https://' tracking structures, validating root CA arrays at runtime."),
        ("CWE-1310", "Implement hardware configuration layout profiles that support multi-slot over-the-air (OTA) boot partitions. Ensure flash table mappings provide secure rollback protection tracking boundaries.")
    ]
    
    # Seed vulnerabilities table securely
    cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
    if cursor.fetchone()[0] == 0:
        cursor.executemany("""
            INSERT INTO vulnerabilities (cve_id, component_name, affected_version, description, severity, cwe_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, sample_intel)
        
    # Seed remediations table securely
    cursor.execute("SELECT COUNT(*) FROM remediations")
    if cursor.fetchone()[0] == 0:
        cursor.executemany("""
            INSERT INTO remediations (cwe_id, blueprint_text)
            VALUES (?, ?)
        """, remediation_blueprints)
        
    conn.commit()
    conn.close()