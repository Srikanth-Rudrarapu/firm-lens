import sqlite3
import os

def initialize_vulnerability_db():
    """
    Initializes a localized relational database schema to act as an offline
    threat intelligence cache. This supports strict air-gapped sandbox execution
    by separating live threat data streams from core binary analysis logic.
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(current_dir, "vulnerabilities.db")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # 1. CORE COGNITIVE INTERFACE: MAPS PUBLIC CVE ENTRIES TO WEAKNESS CODES
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cve_cwe_mapping (
            cve_id TEXT PRIMARY KEY,
            cwe_id TEXT NOT NULL,
            component_target TEXT NOT NULL,
            base_severity TEXT NOT NULL
        )
    """)
    
    # 2. TELEMETRY CACHE: STORES LIVE VOLATILE DATA FROM PUBLIC THREAT FEEDS
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel_cache (
            cve_id TEXT PRIMARY KEY,
            epss_score REAL NOT NULL,
            kev_status INTEGER NOT NULL DEFAULT 0,
            last_synced TEXT NOT NULL,
            FOREIGN KEY(cve_id) REFERENCES cve_cwe_mapping(cve_id) ON DELETE CASCADE
        )
    """)

    # 3. REMEDIATION BLUEPRINTS ARCHIVE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS remediations (
            cwe_id TEXT PRIMARY KEY,
            blueprint_text TEXT NOT NULL
        )
    """)

    # 4. REGULATORY COMPLIANCE FRAMEWORK MAPPINGS (Resolves Hardcoded Reports)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS compliance_mappings (
            cwe_id TEXT PRIMARY KEY,
            nist_sp_800_213 TEXT NOT NULL,
            etsi_en_303_645 TEXT NOT NULL
        )
    """)
    
    # Seed data providing an immediate base layer for Espressif components
    initial_architecture_seeds = [
        ("CVE-2021-28150", "CWE-120", "ESP-IDF Bootloader Suite", "Critical"),
        ("CVE-2020-15048", "CWE-347", "ESP-IDF Secure Boot Engine", "High"),
        ("CVE-2022-35860", "CWE-787", "ESP-IDF Wi-Fi Driver Layer", "High"),
        ("CVE-2021-44732", "CWE-203", "MbedTLS Crypto Hardware Acceleration", "High"),
        ("CVE-2022-30767", "CWE-121", "MbedTLS Handshake Subsystem", "Critical")
    ]

    remediation_blueprints = [
        ("CWE-347", "Enforce hardware-rooted RSA/ECDSA asymmetric signature verification schemes. In your 'sdkconfig', explicitly toggle 'CONFIG_SECURE_BOOT_V2_ENABLED=y' and lock the public key digest irreversibly into the physical eFuse block."),
        ("CWE-311", "Activate the built-in AES-256 transparent Flash Encryption engine. Ensure 'CONFIG_SECURE_FLASH_ENC_ENABLED=y' is enforced in the bootloader layout configuration so unencrypted application partitions cannot be dumped over UART physical diagnostic boundaries."),
        ("CWE-1200", "Configure eFuse restriction parameters to permanently burn access lines. Strip physical JTAG debugging wires and disable direct ROM bootloader download commands ('CONFIG_SECURE_BOOT_DISABLE_ROM_DL_MODE=y') to mitigate runtime physical injection attacks."),
        ("CWE-798", "Purge raw credential values, private keys, and API tokens from code strings. Migrate secret data into an independent, encrypted NVS partition block or handle configuration handshakes dynamically using runtime encrypted key exchanges."),
        ("CWE-312", "Never write plaintext credential artifacts to non-volatile flash buffers. Encrypt the target storage blocks using the Espressif NVS encryption utility API or migrate to runtime storage configurations that clear variables directly from volatile SRAM blocks upon power cycles."),
        ("CWE-327", "Decommission outdated cryptographic signatures like MD5 or primitive XOR obfuscation tables. Refactor codebase routines to utilize strong, hardware-accelerated primitives such as SHA-256 or hardware-managed AES-GCM engine wrappers."),
        ("CWE-134", "Eliminate direct user-controlled arguments inside raw formatting output functions. Replace open format strings with safe positional bounds or rewrite direct print sinks to leverage explicitly protected length variables."),
        ("CWE-319", "Upgrade transport communication pathways from cleartext variants to transport-layer security wrappers. Replace 'mqtt://' and 'http://' endpoints with 'mqtts://' and 'https://' tracking structures, validating root CA arrays at runtime."),
        ("CWE-1310", "Implement hardware configuration layout profiles that support multi-slot over-the-air (OTA) boot partitions. Ensure flash table mappings provide secure rollback protection tracking boundaries.")
    ]

    compliance_seeds = [
        ("CWE-347", "NIST SP 800-213 § 4.2.1 (Secure Device Boot Strapping)", "ETSI EN 303 645 Standard Audit Baseline"),
        ("CWE-311", "NIST SP 800-213 § 4.2.1 (Secure Device Boot Strapping)", "ETSI EN 303 645 Standard Audit Baseline"),
        ("CWE-1200", "NIST SP 800-213 Hardware Security Core", "ETSI EN 303 645 Physical Hardening Metrics"),
        ("CWE-798", "NIST SP 800-213 Data Protection Baseline", "ETSI EN 303 645 Compliance Rule 5.1-1 (No Hardcoded Credentials)"),
        ("CWE-312", "NIST SP 800-213 Storage Security", "ETSI EN 303 645 Data Protection at Rest"),
        ("CWE-327", "NIST SP 800-213 Cryptographic Baseline", "ETSI EN 303 645 Cipher Compliance"),
        ("CWE-134", "NIST SP 800-213 Memory Safety Protection", "ETSI EN 303 645 Secure Software Development"),
        ("CWE-319", "NIST SP 800-213 Transport Security", "ETSI EN 303 645 Protection of Data in Transit"),
        ("CWE-1310", "NIST SP 800-213 Firmware Management Lifecycle", "ETSI EN 303 645 Secure Software Update Engine")
    ]
    
    # Execute batch insertions securely
    for seed in initial_architecture_seeds:
        cursor.execute("INSERT OR IGNORE INTO cve_cwe_mapping VALUES (?, ?, ?, ?)", seed)
        
    for cwe, text in remediation_blueprints:
        cursor.execute("INSERT OR IGNORE INTO remediations VALUES (?, ?)", (cwe, text))

    for cwe, nist, etsi in compliance_seeds:
        cursor.execute("INSERT OR IGNORE INTO compliance_mappings VALUES (?, ?, ?)", (cwe, nist, etsi))
        
    conn.commit()
    conn.close()