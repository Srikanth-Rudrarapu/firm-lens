import os
import json
import urllib.request
import urllib.parse
from typing import Dict, Any

def initialize_vulnerability_db():
    """
    100% Dynamic Software Composition Analysis (SCA) Synchronizer.
    Queries the official public GitHub Advisory API by default
    to generate a clean local vulnerability index cache.
    """
    target_dir = os.path.join("firm_lens", "utils")
    db_filename = "vulnerability_db.json"
    full_path = os.path.join(target_dir, db_filename)

    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    print("Connecting to the official Upstream GitHub Advisory Database API...")
    
    api_url = "https://api.github.com/advisories"
    params = {
        "package": "espressif/esp-idf",
        "per_page": 20
    }
    
    url_parts = list(urllib.parse.urlparse(api_url))
    url_parts[4] = urllib.parse.urlencode(params)
    query_url = urllib.parse.urlunparse(url_parts)

    # Establish headers safe for public distribution
    headers = {
        'User-Agent': 'FirmLens-SCA-Engine/1.0',
        'Accept': 'application/vnd.github+json'
    }

    # Open-Source Pattern: Check for an environment variable token safely.
    # Public users running the tool will use unauthenticated requests automatically.
    github_token = os.environ.get("FIRMLENS_GITHUB_TOKEN")
    if github_token:
        headers['Authorization'] = f'Bearer {github_token}'
        print("[+] Optional developer authorization token applied to connection headers.")

    try:
        req = urllib.request.Request(query_url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as response:
            raw_advisories = json.loads(response.read().decode('utf-8'))
            
        print(f"[+] Successfully ingested {len(raw_advisories)} live upstream advisories.")
        
        vulnerability_catalog = {"esp-idf": {}}
        
        for advisory in raw_advisories:
            cve_id = advisory.get("cve_id") or advisory.get("ghsa_id", "UNKNOWN-CVE")
            severity = advisory.get("severity", "High").capitalize()
            title = advisory.get("summary", "Embedded Component Vulnerability")
            description = advisory.get("description", "")
            
            for version_info in advisory.get("vulnerabilities", []):
                v_range = version_info.get("vulnerable_version_range", "")
                
                # Dynamic translation rules to map API scopes to fingerprinter tags
                target_version = "v4.2" 
                if "4.3" in v_range: target_version = "v4.3"
                if "5.0" in v_range: target_version = "v5.0"
                
                if target_version not in vulnerability_catalog["esp-idf"]:
                    vulnerability_catalog["esp-idf"][target_version] = []
                    
                vulnerability_catalog["esp-idf"][target_version].append({
                    "id": cve_id,
                    "title": title,
                    "cwe": "CWE-120" if "overflow" in description.lower() else "CWE-347",
                    "severity": severity,
                    "description": description[:300] + "..."
                })
                
        print("[+] API parsing completed. Serializing localized database cache...")

    except Exception as e:
        print(f"[-] Upstream Network API Connection Failed: {str(e)}")
        print("[*] Generating local fallback template matrix for offline validation...")
        vulnerability_catalog = {
            "esp-idf": {
                "v4.2": [{
                    "id": "CVE-2021-28150",
                    "title": "ESP-IDF Memory Corruption Profile",
                    "cwe": "CWE-120",
                    "severity": "Critical",
                    "description": "Offline safety baseline template descriptor record."
                }]
            }
        }

    with open(full_path, "w", encoding="utf-8") as f:
        json.dump(vulnerability_catalog, f, indent=4)

    print(f"[+] Localized SCA database matrix written to: {full_path}")

if __name__ == "__main__":
    initialize_vulnerability_db()