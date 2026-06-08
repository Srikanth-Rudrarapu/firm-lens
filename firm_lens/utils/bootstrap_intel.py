import os
import gzip
import sqlite3
import requests
from datetime import datetime

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_DATA_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

def sync_global_threat_feeds():
    """
    Connects to authoritative global security endpoints, streams active exploitation metrics,
    and updates the local relational SQLite cache. Employs memory-isolated streams and 
    atomic batch database transactions to fulfill enterprise performance requirements.
    """
    # Dynamically locate vulnerabilities.db inside the data sibling directory
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    db_path = os.path.join(base_dir, "data", "vulnerabilities.db")
    
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Local database matrix skeleton not initialized at: {db_path}")

    # 1. INGEST AUTHORITY CISA KEV CATALOG LIVE FEED
    try:
        cisa_response = requests.get(CISA_KEV_URL, timeout=15)
        cisa_response.raise_for_status()
        cisa_data = cisa_response.json()
        active_kev_cves = {v["cveID"] for v in cisa_data.get("vulnerabilities", [])}
    except Exception as e:
        raise ConnectionError(f"CISA Threat Ingestion Boundary communication failure: {str(e)}")

    # 2. INGEST COMPRESSED FIRST.org EPSS COEFFICIENT MATRIX STREAM
    try:
        epss_response = requests.get(EPSS_DATA_URL, timeout=30, stream=True)
        epss_response.raise_for_status()
        
        # Decompress the gzipped raw network byte chunk stream directly in volatile memory
        decompressed_data = gzip.decompress(epss_response.content).decode("utf-8")
    except Exception as e:
        raise ConnectionError(f"FIRST.org EPSS Mass Data stream decompression failure: {str(e)}")

    # 3. CONNECT TO RELATIONAL LAYER & EXECUTE ATOMIC INTERSECTION MATCHING
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Identify exactly which CVEs our firmware environment mapping table currently holds
    cursor.execute("SELECT cve_id FROM cve_cwe_mapping")
    monitored_cves = {row[0] for row in cursor.fetchall()}
    
    sync_timestamp = datetime.now().isoformat()
    bulk_insertion_pool = []

    # Parse through the raw mass EPSS CSV stream array line-by-line
    # Row layout matches: cve,epss,percentile
    for line in decompressed_data.splitlines():
        if line.startswith("#") or line.startswith("cve"):
            continue
        
        segments = line.split(",")
        if len(segments) >= 2:
            cve_id = segments[0].strip()
            
            # If the public vulnerability intersects with our monitored ESP32 firmware modules, cache it
            if cve_id in monitored_cves:
                try:
                    epss_score = float(segments[1].strip())
                    kev_flag = 1 if cve_id in active_kev_cves else 0
                    bulk_insertion_pool.append((cve_id, epss_score, kev_flag, sync_timestamp))
                except ValueError:
                    continue

    # 4. EXECUTE ATOMIC SQLITE UPDATE TRANSACTION BOUNDARY
    if bulk_insertion_pool:
        try:
            cursor.executemany("""
                INSERT OR REPLACE INTO threat_intel_cache (cve_id, epss_score, kev_status, last_synced)
                VALUES (?, ?, ?, ?)
            """, bulk_insertion_pool)
            conn.commit()
            return len(bulk_insertion_pool)
        except sqlite3.Error as e:
            conn.rollback()
            raise sqlite3.DatabaseError(f"Relational telemetry update transaction rejected: {str(e)}")
    
    conn.close()
    return 0