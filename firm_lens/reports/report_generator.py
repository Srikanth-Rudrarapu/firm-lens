import os
import json
import html
import sqlite3
from datetime import datetime
from typing import Dict, List, Any
from rich.console import Console
from rich.table import Table
from rich.theme import Theme
from pathlib import Path

class ReportGenerator:
    """
    Industrial-grade Safe Report Orchestrator.
    Protects proprietary analytical thresholds, math calculations, and heuristics
    from client-side exposure via automated output telemetry sanitization.
    """

    def __init__(self, base_dir: str = "reports"):
        self.base_dir = base_dir
        self.theme = Theme({
            "info": "bold cyan", 
            "success": "green", 
            "warning": "yellow", 
            "error": "bold red",
            "title": "bold magenta"
        })
        self.console = Console(theme=self.theme, soft_wrap=True)

        self._analyzer_domain_map = {
            "FingerprintAnalyzer": "Platform Architecture & Component Catalog",
            "SecureBootAnalyzer": "Hardware-Rooted Boot Integrity Assessments",
            "FlashEncryptionAnalyzer": "Data-at-Rest Storage Cryptography Obfuscation",
            "SecretsAnalyzer": "Static Cryptographic Key & Credential Escrow Checks",
            "CryptoAnalyzer": "Cryptographic Primitive Configuration Profiles",
            "ESP32PartitionAnalyzer": "Logical Storage Layout & Boundary Integrity Audits",
            "AppStringAnalyzer": "Application Layer Information Leakage Telemetry",
            "DangerousFunctionAnalyzer": "Memory Safety & Execution Control-Flow Audits",
            "InsecureEndpointAnalyzer": "Infrastructure Interface & Network Surface Mapping",
            "BackdoorAnalyzer": "Unauthorized Access & Maintenance Interface Audits",
            "WeakXORAnalyzer": "Static Obfuscation & Data Masking Vulnerabilities",
            "HardwareInTheLoopFuzzer": "Physical Hardware Device Fuzzing & Interaction",
            "CVEAnalyzer": "Software Composition Analysis & Supply Chain Intel"
        }

        self._id_token_map = {
            "FIRM-FINGER-001": "FL-AUDIT-CORE", "FIRM-SECBOOT-001": "FL-BOOT-V01A",
            "FIRM-SECBOOT-020": "FL-BOOT-E91X", "FIRM-FLASH-001": "FL-HARD-M412",
            "FIRM-SECRET-001": "FL-CRED-908B", "FIRM-CRYPTO-002": "FL-CIPH-C711",
            "FIRM-ESP32-PART-010": "FL-PART-S88E", "FIRM-ESP32-PART-040": "FL-PART-INTEG",
            "FIRM-APP-KEY-001": "FL-CRED-PK99", "FIRM-APP-URL-001": "FL-NETW-SURF",
            "FIRM-ENDPOINT-CLEAR-001": "FL-NETW-TRAF", "FIRM-ENDPOINT-IP-001": "FL-NETW-BNDR",
            "FIRM-BACKDOOR-PATH-001": "FL-EVAD-ROUT", "FIRM-XOR-001": "FL-OBFU-77C1",
            "FIRM-APP-UNSAFEFUNC-001": "FL-MEMS-032E", "FIRM-HITL-001": "FL-HARD-FUZZ"
        }

        self._cwe_fallback_registry = {
            "Missing Secure Boot Signature Sector": ["CWE-347"],
            "Hardware Flash Encryption Appears Disabled": ["CWE-312"],
            "Private Key Marker Found in Firmware": ["CWE-321", "CWE-327"],
            "Hardcoded Static Credentials or Sensitive Secrets Exposed": ["CWE-798", "CWE-312"],
            "Cryptographic Engine Configuration Profile Identified": ["CWE-327", "CWE-328"],
            "Unencrypted Sensitive Data Partition Identified": ["CWE-311", "CWE-312"],
            "Missing Secure Remote Patching Capabilities": ["CWE-1310"],
            "Unbounded Format String Parameter Detected": ["CWE-134", "CWE-120"],
            "Static IPv4 Address Infiltration Boundary": ["CWE-798", "CWE-200"],
            "Hardcoded Public Network Endpoint Target": ["CWE-200"],
            "Cleartext Network Transport Endpoint Discovered": ["CWE-319"],
            "Hidden Administrative/Debug URI Path Discovered": ["CWE-425", "CWE-912"]
        }

    def _abstract_offset(self, raw_offset: Any) -> str:
        try:
            if not raw_offset or raw_offset == "-": return "System Metric Boundary"
            val = int(raw_offset, 16) if isinstance(raw_offset, str) and raw_offset.startswith("0x") else int(raw_offset)
            if val == 0x1000: return "0x1000 [Core Bootloader Sector]"
            elif 0x8000 <= val <= 0xA000: return f"0x{val:X} [Partition Configuration Registry]"
            elif val < 0x10000: return f"0x{val:X} [Internal Vendor ROM Boundary]"
            elif 0x10000 <= val <= 0x1F0000: return f"0x{val:X} [Application Execution Kernel Linker Space]"
            return f"0x{val:X} [Non-Volatile Flash Data Allocation Pool]"
        except Exception:
            return str(raw_offset)

    def _sanitize_telemetry(self, raw_id: str, raw_evidence: str) -> tuple:
        """Maps internal rule IDs to standard FirmLens IDs while preserving exact evidence."""
        secure_id = self._id_token_map.get(raw_id, raw_id)
        return secure_id, str(raw_evidence)

    def _extract_fields(self, f: Any) -> tuple:
        if isinstance(f, dict):
            return (f.get("id", "FIRM-UNK"), f.get("severity", "Medium"), f.get("title", "Generic Vulnerability"), f.get("cwes", []), f.get("evidence", "-"), f.get("offset", "-"), f.get("remediation_blueprint", None))
        return (getattr(f, "id", "FIRM-UNK"), getattr(f, "severity", "Medium"), getattr(f, "title", "Generic Vulnerability"), getattr(f, "cwes", []), getattr(f, "evidence", "-"), getattr(f, "offset", "-"), getattr(f, "remediation_blueprint", None))

    def _get_remediation(self, cwes: List[str], severity: str) -> tuple:
        if str(severity).strip().lower() == "info":
            return ("PASSPORT", "Verification Metric: This diagnostic entry represents successful structural fingerprinting. No remediation required.")
            
        blueprint_text = "Review architectural parameters and implement hardening controls matching this configuration."
        try:
            db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "vulnerabilities.db")
            if os.path.exists(db_path):
                with sqlite3.connect(db_path) as conn:
                    cursor = conn.cursor()
                    for cwe in cwes:
                        cursor.execute("SELECT blueprint_text FROM remediations WHERE UPPER(cwe_id) = ?", (str(cwe).strip().upper(),))
                        row = cursor.fetchone()
                        if row: return ("REMEDIATION", row[0])
        except Exception:
            pass
        return ("REMEDIATION", blueprint_text)
    
    def _fetch_threat_intelligence(self, title: str, cwes: List[str], severity: str) -> dict:
        """
        Authoritative intelligence correlation.
        Assigns live scores if found in SQLite threat cache; otherwise sets explicit null / N/A.
        """
        intel = {
            "active_exploitation": "Not listed in CISA KEV Catalog",
            "epss_score": "N/A",
            "epss_raw": None,
            "nist_sp_800_213": "NIST SP 800-213 Data Protection Baseline",
            "etsi_en_303_645": "ETSI EN 303 645 Standard Audit Baseline",
            "provenance_source": "Firmware Evidence / Local Audit"
        }
        
        try:
            db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "vulnerabilities.db")
            if os.path.exists(db_path):
                with sqlite3.connect(db_path) as conn:
                    cursor = conn.cursor()
                    # 1. Compliance Mappings
                    for cwe in cwes:
                        cursor.execute("SELECT nist_sp_800_213, etsi_en_303_645 FROM compliance_mappings WHERE UPPER(cwe_id) = ?", (str(cwe).strip().upper(),))
                        row = cursor.fetchone()
                        if row:
                            intel["nist_sp_800_213"], intel["etsi_en_303_645"] = row[0], row[1]
                            break
                            
                    # 2. Live Threat Feed Cache
                    for cwe in cwes:
                        cursor.execute(
                            "SELECT t.epss_score, t.kev_status, t.cve_id FROM threat_intel_cache t "
                            "JOIN cve_cwe_mapping m ON t.cve_id = m.cve_id "
                            "WHERE UPPER(m.cwe_id) = ?", 
                            (str(cwe).strip().upper(),)
                        )
                        row = cursor.fetchone()
                        if row:
                            score_val = float(row[0])
                            intel["epss_raw"] = score_val
                            intel["epss_score"] = f"{score_val * 100:.2f}% (Live Threat Feed Cache)"
                            if int(row[1]) == 1:
                                intel["active_exploitation"] = "YES (Confirmed by CISA KEV Catalog)"
                            else:
                                intel["active_exploitation"] = "Not listed in CISA KEV Catalog"
                            intel["provenance_source"] = f"NVD/FIRST/CISA Catalog via {row[2]}"
                            return intel
        except Exception:
            pass

        # Contextual Physical Classification for hardware-bound findings
        physical_keywords = ["HARDWARE", "FLASH", "JTAG", "ENCRYPTION", "PARTITION", "BOOT", "OTA"]
        if any(k in title.upper() for k in physical_keywords):
            intel["epss_score"] = "N/A - Physical Hardware Vector (Not tracked by network EPSS)"
            intel["epss_raw"] = None
            intel["active_exploitation"] = "Requires local physical device access"
            intel["provenance_source"] = "Physical Architecture Metric"
            return intel

        return intel

    def _process_findings(self, results: Dict[str, List[Any]]) -> List[dict]:
        processed = []
        for domain, findings in results.items():
            if not findings: continue
            for f in findings:
                f_id, sev, title, cwes_list, ev, offset, custom_rem = self._extract_fields(f)
                
                f_id = self._sanitize_telemetry(str(f_id), str(ev))[0]
                sev = str(sev).capitalize()
                if sev not in ["Critical", "High", "Medium", "Low", "Info"]: sev = "Info"
                title = str(title or "Unknown Vulnerability")
                ev = self._sanitize_telemetry(str(f_id), str(ev))[1]

                import re
                import ast
                
                raw_ev = getattr(f, 'evidence', [])
                if isinstance(raw_ev, str):
                    if raw_ev.startswith("['") and raw_ev.endswith("']"):
                        try:
                            raw_ev = ast.literal_eval(raw_ev)
                        except Exception:
                            raw_ev = [raw_ev]
                    else:
                        raw_ev = [raw_ev]

                sanitized_ev = []
                for e in raw_ev:
                    e_str = str(e)
                    e_str = re.sub(r'%[0-9]*[sdxXunpclh]', '[format-spec]', e_str)
                    e_str = re.sub(r'(?i)(/(?:idf|lwip|components|esp-idf)+/[^\s]*)', '[path-omitted]', e_str)
                    sanitized_ev.append(e_str)

                if not cwes_list or cwes_list == ["-"] or cwes_list == []:
                    if sev in ["Info", "Low"] and any(k in title.lower() for k in ["fingerprint", "verified", "header"]):
                        cwes_str = "N/A (Operational Check)"
                        cwes_list = []
                    else:
                        cwes_list = self._cwe_fallback_registry.get(title, [])
                        cwes_str = ", ".join(cwes_list) if cwes_list else "TBD (General Weakness Class)"
                else:
                    if isinstance(cwes_list, str): cwes_list = [cwes_list]
                    cwes_str = ", ".join([str(c) for c in cwes_list])

                rem_type, rem_text = self._get_remediation(cwes_list, sev)
                
                if custom_rem:
                    rem_text = custom_rem
                    rem_type = "REMEDIATION"

                intel = self._fetch_threat_intelligence(title, cwes_list, sev)

                processed.append({
                    "domain": domain, "id": f_id, "severity": sev, "title": title,
                    "cwes_list": cwes_list, "cwes_str": cwes_str, 
                    "evidence": sanitized_ev,
                    "offset": self._abstract_offset(offset), "rem_type": rem_type, "rem_text": rem_text, "intel": intel
                })

        return processed

    def _calculate_metrics(self, processed: List[dict]) -> dict:
        m = {"total_findings": 0, "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0}
        for item in processed:
            if "unverified" in item["title"].lower() or "unknown" in item["title"].lower():
                m["info_count"] += 1
                continue
            m["total_findings"] += 1
            if item["severity"] == "Critical": m["critical_count"] += 1
            elif item["severity"] == "High": m["high_count"] += 1
            elif item["severity"] == "Medium": m["medium_count"] += 1
            elif item["severity"] == "Low": m["low_count"] += 1
            elif item["severity"] in ["Info", "Log"]: m["info_count"] += 1
        return m

    def generate(self, results: Dict[str, List[Any]], fmt: str = None, explicit_path: str = None, filename: str = "firmware.bin", asset_name: str = None):
        normalized_results = {self._analyzer_domain_map.get(k, "General Security Audits"): v for k, v in results.items()}
        processed_data = self._process_findings(normalized_results)
        self._generate_terminal(processed_data)

        if fmt:
            for f in (["json", "html"] if fmt == "all" else [fmt]):
                try:
                    base_out = explicit_path if explicit_path and not explicit_path.endswith(f".{f}") else os.path.join(os.path.expanduser("~"), "Downloads", "FirmLens_Reports")
                    
                    if explicit_path and explicit_path.endswith(f".{f}"):
                        target_path = explicit_path
                    else:
                        target_path = os.path.join(base_out, f"{os.path.splitext(filename)[0]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{f}")
                    
                    os.makedirs(os.path.dirname(target_path), exist_ok=True)
                    display_asset = asset_name if asset_name else filename

                    if f == "json": self._generate_json(processed_data, target_path, display_asset)
                    elif f == "html": self._generate_html(processed_data, target_path, display_asset)
                except Exception as e:
                    self.console.print(f"[error]File generation failed for {f}: {e}[/error]")

    def _get_severity_color(self, severity: str) -> str:
        return {"Critical": "bold red", "High": "red", "Medium": "yellow", "Low": "green", "Info": "cyan"}.get(severity, "white")

    def _generate_terminal(self, processed: List[dict]):
        if not processed: return
        table = Table(title="FirmLens Security Analysis Report", header_style="bold magenta")
        table.add_column("Compliance Control Domain", style="cyan", no_wrap=True)
        table.add_column("ID", style="magenta")
        table.add_column("Severity", style="bold")
        table.add_column("Title", style="white")
        table.add_column("CWEs", style="yellow")

        for item in processed:
            table.add_row(item["domain"], item["id"], f"[{self._get_severity_color(item['severity'])}]{item['severity'].upper()}[/]", item["title"], item["cwes_str"])
        self.console.print(table)

        self.console.print("\n[bold underline title]Detailed Evidence Summary Log[/bold underline title]\n")
        for item in processed:
            self.console.print(f"[cyan]{item['domain']}[/cyan] → [bold]{item['id']}[/bold]")
            self.console.print(f"  • Title: {item['title']}")
            self.console.print(f"  • Severity: [{self._get_severity_color(item['severity'])}]{item['severity'].upper()}[/]")
            self.console.print(f"  • CWEs: {item['cwes_str']}")
            self.console.print(f"  • Evidence: [italic]{item['evidence']}[/italic]")
            self.console.print(f"  • Offset: {item['offset']}\n")

    def _generate_json(self, processed: List[dict], path: str, asset_name: str):
        metrics = self._calculate_metrics(processed)
        data = {
            "schema_version": "1.0.0",
            "scan_metadata": {
                "tool": "FirmLens",
                "target_asset": asset_name,
                "timestamp": datetime.now().isoformat(),
                "telemetry_audit_vectors_enforced": len(set(item["domain"] for item in processed)),
                "total_security_anomalies_isolated": metrics["total_findings"],
                "severity_distribution_scoreboard": {
                    "Critical": metrics["critical_count"],
                    "High": metrics["high_count"],
                    "Medium": metrics["medium_count"],
                    "Low": metrics["low_count"],
                    "Info": metrics["info_count"]
                }
            },
            "findings": []
        }

        for item in processed:
            is_vuln = True
            if "N/A" in item["cwes_str"] or "Operational" in item["cwes_str"]:
                safe_cwes = []
                is_vuln = False
            else:
                safe_cwes = [str(c) for c in item.get("cwes_list", [])] if item.get("cwes_list") and item.get("cwes_list") != ["-"] else [item.get("cwes_str", "")]

            active_exp_str = item["intel"].get("active_exploitation", "")
            mapped_exploitation = "unsupported" if "Requires" in active_exp_str else "active" if "YES" in active_exp_str else "inactive"

            intel_payload = {
                "active_exploitation": mapped_exploitation,
                "epss_score": item["intel"].get("epss_raw", None),
                "nist_sp_800_213": item["intel"].get("nist_sp_800_213", ""),
                "etsi_en_303_645": item["intel"].get("etsi_en_303_645", ""),
                "provenance_source": item["intel"].get("provenance_source", "Firmware Evidence")
            }

            data["findings"].append({
                "compliance_control_domain": item["domain"],
                "id": item["id"],
                "severity": item["severity"],
                "title": item["title"],
                "cwes": safe_cwes,
                "is_vulnerability": is_vuln,
                "evidence": item["evidence"], 
                "offsets": [item["offset"]],
                "scope": "global" if "System Metric" in item["offset"] else "local",
                "remediation_blueprint": item["rem_text"],
                "threat_intelligence_telemetry": intel_payload
            })

        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
            self.console.print(f"[success]Structured JSON Security Report Saved:[/success] {path}")
        except Exception as e:
            self.console.print(f"[bold red]Error writing JSON report:[/bold red] {e}")

    def _generate_html(self, processed: List[dict], path: str, asset_name: str):
        metrics = self._calculate_metrics(processed)
        css = """
        <style>
            body { font-family: 'Inter', -apple-system, sans-serif; background: #f8fafc; color: #334155; padding: 40px; }
            .container { max-width: 1200px; margin: auto; }
            .header-card { background: #1e293b; color: white; border-radius: 12px; padding: 30px; margin-bottom: 25px; }
            
            .dashboard-row { display: grid; grid-template-columns: repeat(6, 1fr); gap: 15px; margin-bottom: 25px; }
            .metric-card { background: white; border-radius: 10px; padding: 18px; box-shadow: 0 4px 6px rgba(0,0,0,0.02); border-top: 4px solid #cbd5e1; }
            .metric-card.total { border-top-color: #6366f1; }
            .metric-card.critical { border-top-color: #b91c1c; }
            .metric-card.high { border-top-color: #ef4444; }
            .metric-card.medium { border-top-color: #f97316; }
            .metric-card.low { border-top-color: #16a34a; }
            .metric-card.info { border-top-color: #2563eb; }
            .metric-title { font-size: 0.72rem; text-transform: uppercase; color: #cbd5e1; font-weight: 700; letter-spacing: 0.05em; }
            .metric-value { font-size: 1.6rem; font-weight: 700; margin-top: 5px; color: #ffffff; }
            
            .filter-row { margin-top: 20px; display: flex; gap: 10px; flex-wrap: wrap; }
            .f-btn { background: #334155; border: 1px solid #475569; color: #cbd5e1; padding: 6px 16px; border-radius: 6px; cursor: pointer; font-size: 0.8rem; font-weight: 600; transition: all 0.2s; letter-spacing: 0.02em; }
            .f-btn:hover { border-color: #6366f1; color: white; }
            .f-btn.active { background: #6366f1; color: white; border-color: #6366f1; }
            
            .card { background: white; border-radius: 12px; padding: 25px; box-shadow: 0 4px 6px rgba(0,0,0,0.03); margin-bottom: 25px; border-left: 5px solid #6366f1; }
            
            table { width: 100%; border-collapse: collapse; table-layout: fixed; margin-top: 15px; border-radius: 8px; overflow: hidden; }
            th { text-align: left; background: #6366f1; color: white; padding: 14px 12px; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 700; }
            td { padding: 12px; border-bottom: 1px solid #f1f5f9; font-size: 0.9rem; vertical-align: top; word-wrap: break-word; word-break: normal; color: #334155; }
            .col-id { width: 12%; } .col-sev { width: 10%; } .col-title { width: 25%; } .col-cwe { width: 12%; } .col-off { width: 14%; } .col-ev { width: 17%; } .col-action { width: 10%; }
            
            .Critical { color: #ffffff; background: #b91c1c; padding: 4px 10px; border-radius: 6px; font-weight: bold; font-size: 0.78rem; text-transform: uppercase; display: inline-block; }
            .High { color: #ffffff; background: #ef4444; padding: 4px 10px; border-radius: 6px; font-weight: bold; font-size: 0.78rem; text-transform: uppercase; display: inline-block; }
            .Medium { color: #ffffff; background: #f97316; padding: 4px 10px; border-radius: 6px; font-weight: bold; font-size: 0.78rem; text-transform: uppercase; display: inline-block; }
            .Low { color: #ffffff; background: #16a34a; padding: 4px 10px; border-radius: 6px; font-weight: bold; font-size: 0.78rem; text-transform: uppercase; display: inline-block; }
            .Info { color: #ffffff; background: #2563eb; padding: 4px 10px; border-radius: 6px; font-weight: bold; font-size: 0.78rem; text-transform: uppercase; display: inline-block; }
            code { word-wrap: break-word; word-break: normal; overflow-wrap: anywhere; }

            .evidence-box {
                white-space: pre-wrap;
                word-wrap: break-word;
                word-break: normal;
                overflow-wrap: break-word;
                font-family: monospace;
                font-size: 0.85rem;
                color: #475569;
                max-height: 250px;
                overflow-y: auto;
                display: block;
                padding-right: 5px;
            }
            
            .rem-btn { background: #f1f5f9; border: 1px solid #cbd5e1; color: #475569; padding: 4px 8px; border-radius: 4px; cursor: pointer; font-size: 0.75rem; font-weight: 600; width: 100%; text-align: center; }
            .rem-btn:hover { background: #e2e8f0; color: #1e293b; }
            .remediation-row { background: #fafafa; display: none; }
            
            .remediation-box { padding: 15px; border-left: 4px solid #16a34a; background: #f0fdf4; margin: 5px 0; border-radius: 4px; color: #14532d; font-size: 0.88rem; line-height: 1.4; }
            .remediation-box.passport-box { border-left-color: #6366f1; background: #f5f3ff; color: #4c1d95; }
            .rem-title { font-weight: 700; color: #164e63; margin-bottom: 5px; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.02em; }
            .rem-title.passport-title { color: #4338ca; }
        </style>
        <script>
            function filterBySeverity(sev, btn) {
                document.querySelectorAll('.f-btn').forEach(b => b.classList.remove('active')); btn.classList.add('active');
                document.querySelectorAll('.finding-row').forEach(row => {
                    let match = (sev === 'All' || row.dataset.severity === sev || (sev === 'Info' && (row.dataset.severity === 'Low' || row.dataset.severity === 'Info')));
                    row.style.display = match ? '' : 'none';
                    if(!match) document.getElementById('rem-' + row.id).style.display = 'none';
                });
                document.querySelectorAll('.card').forEach(card => {
                    let visible = Array.from(card.querySelectorAll('.finding-row')).some(r => r.style.display !== 'none');
                    card.style.display = visible ? '' : 'none';
                });
            }
            function toggleRemediation(id) {
                let r = document.getElementById('rem-' + id); r.style.display = (r.style.display === 'none' || r.style.display === '') ? 'table-row' : 'none';
            }
        </script>
        """

        html_layout = f"<html><head><meta charset='UTF-8'><title>{html.escape(asset_name)} - Report</title>{css}</head><body><div class='container'>"
        html_layout += f"<div class='header-card'><h1>FirmLens Security Framework</h1><p>Firmware Target Asset: <code style='background: #f1f5f9; color: #0f172a; padding: 4px 10px; border-radius: 6px; font-weight: bold;'>{html.escape(asset_name)}</code></p><small style='color: #cbd5e1;'>Scan Timestamp Execution: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC</small>"
        html_layout += "<div class='filter-row'><button class='f-btn active' onclick=\"filterBySeverity('All', this)\">All</button><button class='f-btn' onclick=\"filterBySeverity('Critical', this)\">Critical</button><button class='f-btn' onclick=\"filterBySeverity('High', this)\">High</button><button class='f-btn' onclick=\"filterBySeverity('Medium', this)\">Medium</button><button class='f-btn' onclick=\"filterBySeverity('Low', this)\">Low</button><button class='f-btn' onclick=\"filterBySeverity('Info', this)\">Info</button></div></div>"
        
        html_layout += f"<div class='dashboard-row'>" \
                       f"<div class='metric-card total' style='background: #6366f1;'><div class='metric-title'>Total Findings</div><div class='metric-value'>{metrics['total_findings']}</div></div>" \
                       f"<div class='metric-card critical' style='background: #b91c1c;'><div class='metric-title'>Critical</div><div class='metric-value'>{metrics['critical_count']}</div></div>" \
                       f"<div class='metric-card high' style='background: #ef4444;'><div class='metric-title'>High</div><div class='metric-value'>{metrics['high_count']}</div></div>" \
                       f"<div class='metric-card medium' style='background: #f97316;'><div class='metric-title'>Medium</div><div class='metric-value'>{metrics['medium_count']}</div></div>" \
                       f"<div class='metric-card low' style='background: #16a34a;'><div class='metric-title'>Low</div><div class='metric-value'>{metrics['low_count']}</div></div>" \
                       f"<div class='metric-card info' style='background: #2563eb;'><div class='metric-title'>Info</div><div class='metric-value'>{metrics['info_count']}</div></div>" \
                       f"</div>"
                       
        domains = {}
        for item in processed: domains.setdefault(item["domain"], []).append(item)

        row_idx = 0
        for domain, items in domains.items():
            html_layout += f"<div class='card'><h2>{domain}</h2><table><tr><th class='col-id'>ID</th><th class='col-sev'>Severity</th><th class='col-title'>Title</th><th class='col-cwe'>CWEs</th><th class='col-off'>Segment Offset</th><th class='col-ev'>Evidence Summary</th><th class='col-action'>Remediation</th></tr>"
            for i in items:
                r_id = f"row_{row_idx}"; row_idx += 1
                b_class, t_class, t_label, btn = ("passport-box", "passport-title", "Verification Passport:", "View Verification") if i["rem_type"] == "PASSPORT" else ("", "", "Actionable Blueprint:", "View Fix")
                
                ev_list = i.get('evidence', [])
                if len(ev_list) > 1:
                    ev_header = f"<strong style='color:#1e293b;'>Forensic Artifacts Recovered ({len(ev_list)}):</strong><br>"
                else:
                    ev_header = f"<strong style='color:#1e293b;'>Forensic Artifact Recovered (1):</strong><br>"
                
                ev_bullets = "<br>".join([f"&bull; {html.escape(str(e))}" for e in ev_list])
                ev_display = f"{ev_header}{ev_bullets}"

                html_layout += f"<tr class='finding-row' id='{r_id}' data-severity='{i['severity']}'><td><strong>{i['id']}</strong></td><td><span class='{i['severity']}'>{i['severity'].upper()}</span></td><td>{html.escape(i['title'])}</td><td>{i['cwes_str']}</td><td><code style='word-break: break-all;'>{i['offset']}</code></td><td><div class='evidence-box'>{ev_display}</div></td><td><button class='rem-btn' onclick=\"toggleRemediation('{r_id}')\">{btn}</button></td></tr>"
                
                intel = i.get('intel', {})
                active_exp = str(intel.get('active_exploitation', 'N/A'))
                epss = str(intel.get('epss_score', 'N/A'))
                epss_raw_val = intel.get('epss_raw')
                
                if "YES" in active_exp.upper():
                    exp_badge = f"<span style='background: #fee2e2; color: #b91c1c; padding: 4px 10px; border-radius: 6px; font-weight: 800; font-size: 0.75rem; border: 1px solid #fca5a5; display: inline-block; letter-spacing: 0.05em;'>{html.escape(active_exp)}</span>"
                elif "REQUIRES" in active_exp.upper():
                    exp_badge = f"<span style='background: #fef3c7; color: #b45309; padding: 4px 10px; border-radius: 6px; font-weight: 800; font-size: 0.75rem; border: 1px solid #fde68a; display: inline-block; letter-spacing: 0.05em;'>{html.escape(active_exp)}</span>"
                else:
                    exp_badge = f"<span style='background: #f0fdf4; color: #15803d; padding: 4px 10px; border-radius: 6px; font-weight: 800; font-size: 0.75rem; border: 1px solid #bbf7d0; display: inline-block; letter-spacing: 0.05em;'>{html.escape(active_exp)}</span>"

                if epss_raw_val is not None and epss_raw_val >= 0.70:
                    epss_style = "color: #b91c1c; font-weight: 800; font-size: 0.9rem;"
                elif epss == "N/A" or "N/A" in epss or epss_raw_val is None:
                    epss_style = "color: #64748b; font-style: italic;"
                else:
                    epss_style = "color: #334155; font-weight: 700;"

                intel_html = f"""
                <div style='margin-top: 20px; padding: 20px; background: linear-gradient(145deg, #ffffff, #f8fafc); border: 1px solid #cbd5e1; border-radius: 10px; border-left: 5px solid #3b82f6; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);'>
                    <div style='margin-bottom: 15px; border-bottom: 2px solid #f1f5f9; padding-bottom: 10px;'>
                        <strong style='color:#0f172a; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.08em;'>Threat Intelligence & Compliance Telemetry</strong>
                    </div>
                    <div style='display: grid; grid-template-columns: 240px 1fr; gap: 12px 20px; align-items: center; font-size: 0.85rem;'>
                        <div style='font-weight: 700; color: #64748b; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em;'>EPSS Weaponization Probability:</div>
                        <div style='{epss_style}'>{html.escape(epss)}</div>
                        
                        <div style='font-weight: 700; color: #64748b; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em;'>CISA KEV Active Exploitation:</div>
                        <div>{exp_badge}</div>
                        
                        <div style='font-weight: 700; color: #64748b; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; margin-top: 5px;'>NIST SP 800-213 Mapping:</div>
                        <div style='color: #0f172a; font-weight: 600; margin-top: 5px;'>{html.escape(str(intel.get('nist_sp_800_213', 'N/A')))}</div>
                        
                        <div style='font-weight: 700; color: #64748b; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em;'>ETSI EN 303 645 Mapping:</div>
                        <div style='color: #0f172a; font-weight: 600;'>{html.escape(str(intel.get('etsi_en_303_645', 'N/A')))}</div>
                    </div>
                </div>
                """
                
                html_layout += f"<tr id='rem-{r_id}' class='remediation-row'><td colspan='7'><div class='remediation-box {b_class}'><div class='rem-title {t_class}'>{t_label}</div>{html.escape(str(i.get('rem_text', '')))}{intel_html}</div></td></tr>"
                
            html_layout += "</table></div>"

        with open(path, "w", encoding="utf-8") as f: f.write(html_layout + "</div></body></html>")
        self.console.print(f"[success]Interactive HTML Security Report Saved:[/success] {path}")