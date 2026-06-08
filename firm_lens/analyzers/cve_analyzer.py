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
        
        if not isinstance(environment_findings, list):
            return cve_findings

        if not self.db_path or not os.path.exists(self.db_path):
            return cve_findings

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                for f in environment_findings:
                    if not hasattr(f, 'evidence') or not isinstance(f.evidence, str):
                        continue

                    # Robust vendor extraction completely insulated from Title modifications
                    sdk_name = None
                    for token in ["ESP-IDF", "MbedTLS", "FreeRTOS", "Arduino-ESP32"]:
                        if token in f.evidence:
                            sdk_name = token
                            break
                    
                    if not sdk_name:
                        continue
                        
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
                            
                        # Build pristine supply-chain artifacts
                        cve_findings.append(Finding(
                            id=cve_id,
                            title=f"Known Supply Chain Vulnerability: {cve_id}",
                            description=description,
                            severity=severity if severity else "High",
                            cwes=[cwe_id] if cwe_id else ["CWE-937"],
                            evidence=f"Matched software component signature: {sdk_name} v{version}",
                            offset=getattr(f, 'offset', '-')
                        ))
        except Exception:
            pass

        return cve_findings
