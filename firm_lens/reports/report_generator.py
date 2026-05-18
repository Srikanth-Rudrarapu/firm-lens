import os
import json
import html
from datetime import datetime
from typing import Dict, List, Any
from rich.console import Console
from rich.table import Table
from rich.theme import Theme

class ReportGenerator:
    """
    Industrial-grade Safe Report Orchestrator.
    Handles data polymorphism dynamically to guarantee reporting continuity.
    Provides actionable remediation mappings for security findings.
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

        # Enterprise Compliance Remediation Matrix
        self._remediation_db = {
            "CWE-347": "Enforce hardware-rooted RSA/ECDSA asymmetric signature verification schemes. In your 'sdkconfig', explicitly toggle 'CONFIG_SECURE_BOOT_V2_ENABLED=y' and lock the public key digest irreversibly into the physical eFuse block.",
            "CWE-311": "Activate the built-in AES-256 transparent Flash Encryption engine. Ensure 'CONFIG_SECURE_FLASH_ENC_ENABLED=y' is enforced in the bootloader layout configuration so unencrypted application partitions cannot be dumped over UART physical diagnostic boundaries.",
            "CWE-1200": "Configure eFuse restriction parameters to permanently burn access lines. Strip physical JTAG debugging wires and disable direct ROM bootloader download commands ('CONFIG_SECURE_BOOT_DISABLE_ROM_DL_MODE=y') to mitigate runtime physical injection attacks.",
            "CWE-798": "Purge raw credential values, private keys, and API tokens from code strings. Migrate secret data into an independent, encrypted NVS partition block or handle configuration handshakes dynamically using runtime encrypted key exchanges.",
            "CWE-312": "Never write plaintext credential artifacts to non-volatile flash buffers. Encrypt the target storage blocks using the Espressif NVS encryption utility API or migrate to runtime storage configurations that clear variables directly from volatile SRAM blocks upon power cycles.",
            "CWE-327": "Decommission outdated cryptographic signatures like MD5 or primitive XOR obfuscation tables. Refactor codebase routines to utilize strong, hardware-accelerated primitives such as SHA-256 or hardware-managed AES-GCM engine wrappers.",
            "CWE-328": "Deprecate weak collision-prone hashing functions (MD5/SHA1). Replace hashing engines with SHA-256 or SHA-512 libraries, taking advantage of the hardware crypto-acceleration sub-blocks present on modern ESP32 architectures.",
            "CWE-134": "Eliminate direct user-controlled arguments inside raw formatting output functions. Replace open format strings with safe positional bounds or rewrite direct print sinks to leverage explicitly protected length variables.",
            "CWE-120": "Replace bounded buffer overflow candidates (strcpy, sprintf) with strict alternative implementations (strncpy, snprintf). Validate array boundary indices prior to writing data blocks into memory segments to avoid heap/stack contamination.",
            "CWE-489": "Deactivate debug logic and diagnostic tracking instrumentation hooks prior to preparing production binary outputs. Strip 'X-Debug-Token' variables and remove verbose terminal logging macros using compiler flag controls.",
            "CWE-912": "Purge diagnostic administrative routing tables, open test scripts, or physical backdoor routing segments from distribution images. Enforce strict token-based authorization frameworks across every exposed local and network API path.",
            "CWE-425": "Enforce robust server-side structural access validation matrices. Unauthenticated routing tokens must never grant execution paths to internal device configuration operations simply by guessing hidden path extensions.",
            "CWE-319": "Upgrade transport communication pathways from cleartext variants to transport-layer security wrappers. Replace 'mqtt://' and 'http://' endpoints with 'mqtts://' and 'https://' tracking structures, validating root CA arrays at runtime."
        }

    def generate(self, results: Dict[str, List[Any]], fmt: str = "terminal", explicit_path: str = None, filename: str = "firmware.bin"):
        """Orchestrates report generation safely for requested formats."""
        self._generate_terminal(results)

        formats_to_gen = ["json", "html"] if fmt == "all" else [fmt]
        for f in formats_to_gen:
            if f == "terminal":
                continue
                
            try:
                target_path = self._resolve_path(explicit_path, f)
                if f == "json":
                    self._generate_json(results, target_path, filename)
                elif f == "html":
                    self._generate_html(results, target_path, filename)
            except Exception as e:
                self.console.print(f"[error]❌ File generation pipeline failed for format '{f}': {str(e)}[/error]")

    def _resolve_path(self, explicit_path: str, extension: str) -> str:
        """Ensures correct file extensions and handles directory creation paths safely."""
        if explicit_path:
            if not explicit_path.lower().endswith(f".{extension}"):
                resolved = f"{explicit_path}.{extension}"
            else:
                resolved = explicit_path
            parent_dir = os.path.dirname(os.path.abspath(resolved))
            os.makedirs(parent_dir, exist_ok=True)
            return resolved
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        session_dir = os.path.join(self.base_dir, f"audit_{timestamp}")
        os.makedirs(session_dir, exist_ok=True)
        return os.path.join(session_dir, f"security_report.{extension}")

    def _get_severity_color(self, severity: str) -> str:
        """Maps severity levels to Rich terminal colors."""
        mapping = {
            "Critical": "bold red", "High": "red", "Medium": "yellow", "Low": "blue", "Info": "cyan"
        }
        return mapping.get(str(severity), "white")

    def _extract_fields(self, f: Any) -> tuple:
        """Polymorphic parser: extracts metrics cleanly whether the asset is a class object or dict."""
        if isinstance(f, dict):
            return (
                f.get("id", "FIRM-UNK"),
                f.get("severity", "Medium"),
                f.get("title", "Generic Vulnerability Metric"),
                f.get("cwes", []),
                f.get("evidence", "-"),
                f.get("offset", "-")
            )
        else:
            return (
                getattr(f, "id", "FIRM-UNK"),
                getattr(f, "severity", "Medium"),
                getattr(f, "title", "Generic Vulnerability Metric"),
                getattr(f, "cwes", []),
                getattr(f, "evidence", "-"),
                getattr(f, "offset", "-")
            )

    def _get_remediation(self, cwes: List[str], severity: str) -> tuple:
        """Extracts text context conditionally based on finding taxonomy and severity limits."""
        if str(severity).strip().lower() == "info":
            return (
                "PASSPORT", 
                "Verification Metric: This diagnostic structural entry represents successful system environment fingerprinting or passive operational verification tracking. No defensive remediation or security hardening patch modifications are required for this block layout."
            )
            
        for cwe in cwes:
            if cwe in self._remediation_db:
                return ("REMEDIATION", self._remediation_db[cwe])
        return ("REMEDIATION", "Review architectural parameters and cross-reference Espressif engineering guidelines to implement hardening controls matching this configuration.")

    def _calculate_metrics(self, results: Dict[str, List[Any]]) -> dict:
        """Helper method to count vulnerability densities cleanly across all submodules."""
        total_findings = sum(len(f_list) for f_list in results.values())
        critical_count = sum(1 for f_list in results.values() for f in f_list if getattr(f, 'severity', dict().get('severity')) == "Critical")
        high_count = sum(1 for f_list in results.values() for f in f_list if getattr(f, 'severity', dict().get('severity')) == "High")
        medium_count = sum(1 for f_list in results.values() for f in f_list if getattr(f, 'severity', dict().get('severity')) == "Medium")
        info_count = sum(1 for f_list in results.values() for f in f_list if getattr(f, 'severity', dict().get('severity')) in ["Low", "Info"])
        
        return {
            "total_findings": total_findings,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "info_count": info_count
        }

    def _generate_terminal(self, results: Dict[str, List[Any]]):
        """Generates the high-contrast terminal report with defensive error boundaries."""
        table = Table(title="FirmLens Security Analysis Report", header_style="bold magenta")
        table.add_column("Analyzer", style="cyan", no_wrap=True)
        table.add_column("ID", style="magenta")
        table.add_column("Severity", style="bold")
        table.add_column("Title", style="white")
        table.add_column("CWEs", style="yellow")

        for analyzer, findings in results.items():
            if not findings:
                continue
            for f in findings:
                try:
                    f_id, severity, title, cwes_list, _, _ = self._extract_fields(f)
                    sev_color = self._get_severity_color(severity)
                    cwes_str = ", ".join(cwes_list) if cwes_list else "-"
                    table.add_row(analyzer, f_id, f"[{sev_color}]{severity}[/]", title, cwes_str)
                except Exception:
                    pass
        
        try:
            self.console.print(table)
        except Exception as e:
            self.console.print(f"[error]Terminal Table Render aborted due to string symbols constraints: {e}[/error]")

        # Detailed Forensic Evidence Summary Log Matrix
        self.console.print("\n[bold underline title]Detailed Evidence Summary Log[/bold underline title]\n")
        for analyzer, findings in results.items():
            if not findings:
                continue
            for f in findings:
                try:
                    f_id, severity, title, cwes_list, evidence, offset = self._extract_fields(f)
                    sev_color = self._get_severity_color(severity)
                    off_str = hex(offset) if isinstance(offset, int) else str(offset)
                    
                    self.console.print(f"[cyan]{analyzer}[/cyan] → [bold]{f_id}[/bold]")
                    self.console.print(f"  • Title: {title}")
                    self.console.print(f"  • Severity: [{sev_color}]{severity}[/]")
                    self.console.print(f"  • CWEs: {', '.join(cwes_list) if cwes_list else '-'}")
                    
                    self.console.print("  • Evidence: ", end="")
                    self.console.print(str(evidence or '-'), style="italic", highlight=False)
                    self.console.print(f"  • Offset: {off_str}\n")
                except Exception:
                    pass

    def _generate_json(self, results: Dict[str, List[Any]], path: str, filename: str):
        """Saves findings in machine-readable JSON format with explicit remediation entries."""
        metrics = self._calculate_metrics(results)
        
        data = {
            "scan_metadata": {
                "tool": "FirmLens",
                "target_firmware": filename,
                "timestamp": datetime.now().isoformat(),
                "active_modules_executed": len(results),
                "total_findings_isolated": metrics["total_findings"],
                "severity_distribution": {
                    "critical": metrics["critical_count"],
                    "high": metrics["high_count"],
                    "medium": metrics["medium_count"],
                    "info": metrics["info_count"]
                }
            },
            "findings": []
        }
        
        for analyzer, findings in results.items():
            if not findings: continue
            for f in findings:
                try:
                    f_id, severity, title, cwes_list, evidence, offset = self._extract_fields(f)
                    off_str = hex(offset) if isinstance(offset, int) else str(offset)
                    _, rem_text = self._get_remediation(cwes_list, severity)
                    data["findings"].append({
                        "analyzer": analyzer,
                        "id": f_id,
                        "severity": severity,
                        "title": title,
                        "cwes": cwes_list,
                        "evidence": str(evidence),
                        "offset": off_str,
                        "remediation": rem_text
                    })
                except Exception:
                    pass

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        self.console.print(f"[success]✔ Machine-readable JSON report saved successfully to:[/success] {path}")

    def _generate_html(self, results: Dict[str, List[Any]], path: str, filename: str):
        """Generates a professional HTML report with premium blue tables and expandable contextual drawer toggles."""
        metrics = self._calculate_metrics(results)
        escaped_filename = html.escape(filename)
        
        css = """
        <style>
            body { font-family: 'Inter', -apple-system, sans-serif; background: #f8fafc; color: #334155; padding: 40px; }
            .container { max-width: 1200px; margin: auto; }
            .header-card { background: #1e293b; color: white; border-radius: 12px; padding: 30px; margin-bottom: 25px; }
            
            .dashboard-row { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-bottom: 25px; }
            .metric-card { background: white; border-radius: 10px; padding: 18px; box-shadow: 0 4px 6px rgba(0,0,0,0.02); border-top: 4px solid #cbd5e1; }
            .metric-card.total { border-top-color: #6366f1; }
            .metric-card.critical { border-top-color: #ef4444; }
            .metric-card.high { border-top-color: #f97316; }
            .metric-card.medium { border-top-color: #eab308; }
            .metric-card.info { border-top-color: #06b6d4; }
            .metric-title { font-size: 0.72rem; text-transform: uppercase; color: #64748b; font-weight: 700; letter-spacing: 0.05em; }
            .metric-value { font-size: 1.6rem; font-weight: 700; margin-top: 5px; color: #1e293b; }
            
            .filter-row { margin-top: 20px; display: flex; gap: 10px; flex-wrap: wrap; }
            .f-btn { background: #334155; border: 1px solid #475569; color: #cbd5e1; padding: 6px 16px; border-radius: 6px; cursor: pointer; font-size: 0.8rem; font-weight: 600; transition: all 0.2s; letter-spacing: 0.02em; }
            .f-btn:hover { border-color: #6366f1; color: white; }
            .f-btn.active { background: #6366f1; color: white; border-color: #6366f1; }
            
            .card { background: white; border-radius: 12px; padding: 25px; box-shadow: 0 4px 6px rgba(0,0,0,0.03); margin-bottom: 25px; border-left: 5px solid #6366f1; }
            
            table { width: 100%; border-collapse: collapse; table-layout: fixed; margin-top: 15px; border-radius: 8px; overflow: hidden; }
            th { text-align: left; background: #6366f1; color: white; padding: 14px 12px; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 700; }
            td { padding: 12px; border-bottom: 1px solid #f1f5f9; font-size: 0.9rem; vertical-align: top; word-wrap: break-word; }
            .col-id { width: 12%; } .col-sev { width: 10%; } .col-title { width: 25%; } .col-cwe { width: 12%; } .col-off { width: 10%; } .col-ev { width: 21%; } .col-action { width: 10%; }
            
            .Critical { color: #b91c1c; background: #fee2e2; padding: 3px 8px; border-radius: 5px; font-weight: bold; font-size: 0.8rem; border: 1px solid #fecaca; }
            .High { color: #9a3412; background: #ffedd5; padding: 3px 8px; border-radius: 5px; font-weight: bold; font-size: 0.8rem; border: 1px solid #fed7aa; }
            .Medium { color: #854d0e; background: #fef9c3; padding: 3px 8px; border-radius: 5px; font-weight: bold; font-size: 0.8rem; border: 1px solid #fef08a; }
            .Low { color: #1e3a8a; background: #dbeafe; padding: 3px 8px; border-radius: 5px; font-weight: bold; font-size: 0.8rem; border: 1px solid #bfdbfe; }
            .Info { color: #065f46; background: #d1fae5; padding: 3px 8px; border-radius: 5px; font-weight: bold; font-size: 0.8rem; border: 1px solid #a7f3d0; }
            code { background: #f1f5f9; color: #475569; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 0.85em; }
            
            .rem-btn { background: #f1f5f9; border: 1px solid #cbd5e1; color: #475569; padding: 4px 8px; border-radius: 4px; cursor: pointer; font-size: 0.75rem; font-weight: 600; width: 100%; text-align: center; }
            .rem-btn:hover { background: #e2e8f0; color: #1e293b; }
            .remediation-row { background: #fafafa; display: none; }
            
            /* Styled Dynamic Drawers */
            .remediation-box { padding: 15px; border-left: 4px solid #10b981; background: #f0fdf4; margin: 5px 0; border-radius: 4px; color: #14532d; font-size: 0.88rem; line-height: 1.4; }
            .remediation-box.passport-box { border-left-color: #06b6d4; background: #ecfeff; color: #164e63; }
            .rem-title { font-weight: 700; color: #065f46; margin-bottom: 5px; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.02em; }
            .rem-title.passport-title { color: #0891b2; }
        </style>
        """

        script = """
        <script>
            function filterBySeverity(severity, btn) {
                document.querySelectorAll('.f-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                
                const rows = document.querySelectorAll('.finding-row');
                rows.forEach(row => {
                    const rowSev = row.dataset.severity;
                    let isMatch = false;
                    
                    if (severity === 'All') isMatch = true;
                    else if (severity === 'Critical' && rowSev === 'Critical') isMatch = true;
                    else if (severity === 'High' && rowSev === 'High') isMatch = true;
                    else if (severity === 'Medium' && rowSev === 'Medium') isMatch = true;
                    else if (severity === 'Info' && (rowSev === 'Low' || rowSev === 'Info')) isMatch = true;

                    if (isMatch) {
                        row.classList.remove('hidden-row');
                        row.style.display = '';
                    } else {
                        row.classList.add('hidden-row');
                        row.style.display = 'none';
                        const remRow = document.getElementById('rem-' + row.id);
                        if(remRow) remRow.style.display = 'none';
                    }
                });

                document.querySelectorAll('.card').forEach(card => {
                    const totalRows = card.querySelectorAll('.finding-row').length;
                    const hiddenRows = card.querySelectorAll('.finding-row.hidden-row').length;
                    
                    if (totalRows === hiddenRows && severity !== 'All') {
                        card.style.display = 'none';
                    } else {
                        card.style.display = '';
                    }
                });
            }

            function toggleRemediation(rowId) {
                const remRow = document.getElementById('rem-' + rowId);
                if (remRow.style.display === 'none' || remRow.style.display === '') {
                    remRow.style.display = 'table-row';
                } else {
                    remRow.style.display = 'none';
                }
            }
        </script>
        """

        html_start = f"""
        <html>
        <head>
            <meta charset="utf-8">
            <title>🛡️ {escaped_filename} - Report</title>
            {css}
            {script}
        </head>
        <body>
        <div class='container'>
            <div class='header-card'>
                <h1>FirmLens Security Analysis Framework</h1>
                <p>Selected Firmware: <code style='background: #334155; color: #f8fafc; padding: 4px 8px; border-radius: 4px;'>{escaped_filename}</code></p>
                <small style='color: #94a3b8;'>Scan Timestamp Execution: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC</small>
                
                <div class='filter-row'>
                    <button class='f-btn active' onclick="filterBySeverity('All', this)">All</button>
                    <button class='f-btn' onclick="filterBySeverity('Critical', this)">Critical</button>
                    <button class='f-btn' onclick="filterBySeverity('High', this)">High</button>
                    <button class='f-btn' onclick="filterBySeverity('Medium', this)">Medium</button>
                    <button class='f-btn' onclick="filterBySeverity('Info', this)">Info</button>
                </div>
            </div>
            
            <div class='dashboard-row'>
                <div class='metric-card total'>
                    <div class='metric-title'>Total Findings</div>
                    <div class='metric-value'>{metrics['total_findings']}</div>
                </div>
                <div class='metric-card critical'>
                    <div class='metric-title'>Critical</div>
                    <div class='metric-value' style='color: #ef4444;'>{metrics['critical_count']}</div>
                </div>
                <div class='metric-card high'>
                    <div class='metric-title'>High</div>
                    <div class='metric-value' style='color: #f97316;'>{metrics['high_count']}</div>
                </div>
                <div class='metric-card medium'>
                    <div class='metric-title'>Medium</div>
                    <div class='metric-value' style='color: #eab308;'>{metrics['medium_count']}</div>
                </div>
                <div class='metric-card info'>
                    <div class='metric-title'>Info</div>
                    <div class='metric-value' style='color: #06b6d4;'>{metrics['info_count']}</div>
                </div>
            </div>
        """

        content = ""
        row_counter = 0
        for analyzer, findings in results.items():
            if not findings: continue
            content += f"<div class='card'><h2>{analyzer}</h2>"
            content += "<table><tr><th class='col-id'>ID</th><th class='col-sev'>Severity</th><th class='col-title'>Title</th><th class='col-cwe'>CWEs</th><th class='col-off'>Offset</th><th class='col-ev'>Evidence</th><th class='col-action'>Remediation</th></tr>"
            for f in findings:
                try:
                    f_id, severity, title, cwes_list, evidence, offset = self._extract_fields(f)
                    cwes_str = ", ".join(cwes_list) if cwes_list else "-"
                    off_str = hex(offset) if isinstance(offset, int) else str(offset)
                    
                    escaped_evidence = html.escape(str(evidence or '-'))
                    escaped_title = html.escape(str(title or ''))
                    
                    # Dynamically compute context parameters to handle Info verification rows natively
                    rem_type, remediation_text = self._get_remediation(cwes_list, severity)
                    escaped_rem = html.escape(remediation_text)

                    box_class = "passport-box" if rem_type == "PASSPORT" else ""
                    title_class = "passport-title" if rem_type == "PASSPORT" else ""
                    title_label = "🛡️ Security Verification Passport:" if rem_type == "PASSPORT" else "🛡️ Actionable Engineering Remediation Blueprint:"
                    btn_label = "View Verification" if rem_type == "PASSPORT" else "View Fix"

                    row_id = f"row_{row_counter}"
                    row_counter += 1

                    content += f"""
                    <tr class='finding-row' id='{row_id}' data-severity='{severity}'>
                        <td><strong>{f_id}</strong></td>
                        <td><span class='{severity}'>{severity}</span></td>
                        <td>{escaped_title}</td>
                        <td>{cwes_str}</td>
                        <td><code>{off_str}</code></td>
                        <td><code>{escaped_evidence}</code></td>
                        <td><button class='rem-btn' onclick="toggleRemediation('{row_id}')">{btn_label}</button></td>
                    </tr>
                    <tr class='remediation-row' id='rem-{row_id}'>
                        <td colspan='7'>
                            <div class='remediation-box {box_class}'>
                                <div class='rem-title {title_class}'>{title_label}</div>
                                {escaped_rem}
                            </div>
                        </td>
                    </tr>"""
                except Exception:
                    pass
            content += "</table></div>"

        with open(path, "w", encoding="utf-8") as f:
            f.write(html_start + content + "</div></body></html>")
        self.console.print(f"[success]✔ Professional HTML Report compiled and saved successfully to:[/success] {path}")