import os
import sqlite3
import re
from typing import List, Any
from firm_lens.utils.findings import Finding

class CVEAnalyzer:
    """
    Industrial-grade Dynamic Threat Intelligence Engine.
    Queries an offline-first relational vulnerability database with robust version matching.
    """
    def __init__(self, db_path: str = None):
        if db_path is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            possible_paths = [
                os.path.join(current_dir, "..", "data", "vulnerabilities.db"),
                os.path.join(current_dir, "..", "utils", "vulnerabilities.db"),
                os.path.join(current_dir, "vulnerabilities.db")
            ]
            self.db_path = None
            for p in possible_paths:
                if os.path.exists(p):
                    self.db_path = p
                    break
        else:
            self.db_path = db_path

    def run(self, environment_findings: Any) -> List[Finding]:
        cve_findings = []
        
        # Type Safety Guard - Prevents crashing if the main execution loop accidentally feeds this module a string.
        if not isinstance(environment_findings, list):
            return cve_findings

        if not self.db_path or not os.path.exists(self.db_path):
            return cve_findings

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            for f in environment_findings:
                # Secondary Type Guard
                if not hasattr(f, 'title') or not isinstance(f.title, str):
                    continue

                #  Data Normalization - Converts "Detected ESP-IDF SDK Core Layer" -> "ESP-IDF" to match the database exactly.
                extracted_name = f.title.replace("Detected ", "").replace(" SDK", "").strip()
                sdk_name = extracted_name.split()[0] 
                
                version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', f.evidence)
                if not version_match:
                    continue
                    
                version = version_match.group(1)
                major_minor = ".".join(version.split(".")[:2])

                query = """
                    SELECT cve_id, description, severity, cwe_id 
                    FROM vulnerabilities 
                    WHERE component_name = ? AND affected_version LIKE ?
                """
                
                cursor.execute(query, (sdk_name, f"%{major_minor}%"))
                rows = cursor.fetchall()

                for row in rows:
                    cve_id, description, severity, cwe_id = row
                    
                    if any(cve.id == cve_id for cve in cve_findings):
                        continue
                        
                    cve_findings.append(Finding(
                        id=cve_id,
                        title=f"Known Exploit Vector in {sdk_name}",
                        description=description,
                        severity=severity if severity else "Critical",
                        cwes=[cwe_id] if cwe_id else ["CWE-937"],
                        evidence=f"Discovered via SBOM version fingerprint: {version}",
                        offset=f.offset if f.offset else "-",
                        component="supply_chain"
                    ))
                    
            conn.close()
        except Exception:
            pass

        return cve_findings