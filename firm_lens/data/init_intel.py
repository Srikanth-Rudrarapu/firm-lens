import sqlite3
import os

def initialize_vulnerability_db():
    # Dynamically resolve the path to the same directory this script resides in
    current_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(current_dir, "vulnerabilities.db")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create enterprise schema
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
    
    # Sample industrial payload dataset
    sample_intel = [
        ("CVE-2021-28150", "ESP-IDF", "4.2", "Memory corruption leading to arbitrary code execution via custom Wi-Fi frames.", "Critical", "CWE-120"),
        ("CVE-2020-15048", "ESP-IDF", "4.2", "Improper verification of signatures allows bootloader restriction bypass.", "High", "CWE-347"),
        ("CVE-2022-35860", "ESP-IDF", "4.4", "Heap-based buffer overflow in the network interface controller subsystem.", "High", "CWE-787"),
        ("CVE-2021-44732", "MbedTLS", "2.16", "Side-channel vulnerability in modular exponentiation allows private key extraction.", "High", "CWE-203"),
        ("CVE-2022-30767", "MbedTLS", "2.28.0", "Stack-based buffer overflow during handshake message processing.", "Critical", "CWE-121")
    ]
    
    # Avoid duplicate seeding if running it multiple times
    cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
    if cursor.fetchone()[0] == 0:
        cursor.executemany("""
            INSERT INTO vulnerabilities (cve_id, component_name, affected_version, description, severity, cwe_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, sample_intel)
    
    conn.commit()
    conn.close()