import os  # <-- FIX: Missing import that causes linter/runtime path check failure
import sqlite3
from typing import List
from firm_lens.utils.findings import Finding

class CVEAnalyzer:
    """
    Industrial-grade Dynamic Threat Intelligence Engine.
    Queries an offline-first relational vulnerability database.
    """
    def __init__(self, db_path: str = None):
        if db_path is None:
            # Dynamically look inside the package data directory relative to this file
            current_dir = os.path.dirname(os.path.abspath(__file__))
            self.db_path = os.path.join(current_dir, "..", "data", "vulnerabilities.db")
        else:
            self.db_path = db_path

    def run(self, environment_findings: List[Finding]) -> List[Finding]:
        """Dynamically maps extracted SDK versions against local threat intel."""
        cve_findings = []
        
        if not os.path.exists(self.db_path):
            return cve_findings

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for f in environment_findings:
                sdk_name = f.title.replace("Detected ", "").replace(" SDK", "").strip()
                
                # Robust extraction to grab the semantic version number (e.g., 4.2)
                version_parts = [word for word in f.evidence.split() if any(c.isdigit() for c in word)]
                if not version_parts:
                    continue
                # strip away common prefix/suffix labels like 'v' or build tags
                version = version_parts[0].lower().split("version")[-1].strip("v:")

                query = """
                    SELECT cve_id, description, severity, cwe_id 
                    FROM vulnerabilities 
                    WHERE component_name = ? AND affected_version = ?
                """
                cursor.execute(query, (sdk_name, version))
                rows = cursor.fetchall()

                for row in rows:
                    cve_id, description, severity, cwe_id = row
                    cve_findings.append(Finding(
                        id=cve_id,
                        title=f"Known Exploit Vector in {sdk_name}",
                        description=description,
                        severity=severity if severity else "High",
                        cwes=[cwe_id] if cwe_id else ["CWE-937"],
                        evidence=f"Discovered via SBOM version fingerprint: {version}",
                        offset=f.offset if f.offset else "-",
                        component="supply_chain"
                    ))
                    
            conn.close()
        except Exception as e:
            # Prevents quiet failures during portfolio verification runs
            print(f"[-] CVE Intel Pipeline Exception: {str(e)}")

        return cve_findings