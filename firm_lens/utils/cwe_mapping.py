"""
Central CWE mapping used across FirmLens analyzers.

This file provides a single source of truth for mapping internal
finding categories to CWE identifiers. It helps ensure consistency
across all analyzers and improves the clarity of the final report.
"""

CWE_MAP = {
    # Secure boot / bootloader integrity
    "secure_boot": "CWE-302",                 # Authentication bypass / missing enforcement
    "bootloader_integrity": "CWE-353",        # Missing cryptographic signature verification

    # Flash encryption / data-at-rest protection
    "flash_encryption": "CWE-311",            # Missing encryption of sensitive data

    # Hardcoded secrets
    "hardcoded_secrets": "CWE-798",           # Hardcoded credentials
    "hardcoded_keys": "CWE-321",              # Use of hardcoded cryptographic keys

    # Weak or deprecated cryptography
    "weak_crypto": "CWE-327",                 # Use of broken or risky crypto
    "deprecated_hash": "CWE-328",             # Weak hashing algorithm

    # Insecure network endpoints
    "insecure_http": "CWE-319",               # Cleartext transmission of sensitive data
    "insecure_mqtt": "CWE-319",
    "insecure_ble": "CWE-916",                # Improper access control for BLE

    # Dangerous functions / memory safety
    "unsafe_functions": "CWE-120",            # Buffer overflow
    "unsafe_memory_ops": "CWE-119",           # Memory corruption

    # Backdoor / debug interfaces
    "backdoor": "CWE-912",                    # Hidden functionality
    "debug_strings": "CWE-489",               # Active debug code

    # Weak XOR or custom obfuscation
    "weak_xor": "CWE-327",

    # Partition table issues
    "partition_misconfig": "CWE-665",         # Improper initialization / configuration
    "missing_nvs": "CWE-922",                 # Sensitive data storage without protection
}
