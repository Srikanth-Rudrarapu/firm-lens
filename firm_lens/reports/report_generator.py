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

    def generate(self, results: Dict[str, List[Any]], fmt: str = "terminal", explicit_path: str = None):
        """Orchestrates report generation safely for requested formats."""
        # 1. Execute Terminal Render Safely
        self._generate_terminal(results)

        # 2. Map Multi-Format Outflows
        formats_to_gen = ["json", "html"] if fmt == "all" else [fmt]
        for f in formats_to_gen:
            if f == "terminal":
                continue
                
            try:
                target_path = self._resolve_path(explicit_path, f)
                if f == "json":
                    self._generate_json(results, target_path)
                elif f == "html":
                    self._generate_html(results, target_path)
            except Exception as e:
                self.console.print(f"[error]❌ File generation pipeline failed for format '{f}': {str(e)}[/error]")

    def _resolve_path(self, explicit_path: str, extension: str) -> str:
        """Ensures correct file extensions and handles directory creation paths safely."""
        if explicit_path:
            if not explicit_path.lower().endswith(f".{extension}"):
                resolved = f"{explicit_path}.{extension}"
            else:
                resolved = explicit_path
            # Guarantee the parent directory structure exists
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

        # Detailed Evidence Trace print
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
                    # Print raw binary markers safely by neutralizing Rich markup parsing bugs
                    self.console.print("  • Evidence: ", end="")
                    self.console.print(str(evidence or '-'), style="italic", highlight=False)
                    self.console.print(f"  • Offset: {off_str}\n")
                except Exception:
                    pass

    def _generate_json(self, results: Dict[str, List[Any]], path: str):
        """Saves findings in machine-readable JSON format with offsets securely."""
        data = {
            "audit_info": {"tool": "FirmLens", "timestamp": datetime.now().isoformat()},
            "findings": []
        }
        for analyzer, findings in results.items():
            if not findings: continue
            for f in findings:
                try:
                    f_id, severity, title, cwes_list, evidence, offset = self._extract_fields(f)
                    off_str = hex(offset) if isinstance(offset, int) else str(offset)
                    data["findings"].append({
                        "analyzer": analyzer,
                        "id": f_id,
                        "severity": severity,
                        "title": title,
                        "cwes": cwes_list,
                        "evidence": str(evidence),
                        "offset": off_str
                    })
                except Exception:
                    pass

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        self.console.print(f"[success]✔ JSON report saved:[/success] {path}")

    def _generate_html(self, results: Dict[str, List[Any]], path: str):
        """Generates a professional HTML report with explicit layout escaping."""
        css = """
        <style>
            body { font-family: 'Inter', -apple-system, sans-serif; background: #f8fafc; color: #334155; padding: 50px; }
            .container { max-width: 1200px; margin: auto; }
            .header-card { background: #1e293b; color: white; border-radius: 12px; padding: 30px; margin-bottom: 25px; }
            .filter-row { margin-top: 20px; display: flex; gap: 12px; }
            .f-btn { background: #334155; border: 1px solid #475569; color: #cbd5e1; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 0.85rem; }
            .f-btn.active { background: #6366f1; color: white; border-color: #6366f1; font-weight: bold; }
            .card { background: white; border-radius: 12px; padding: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); margin-bottom: 25px; border-left: 5px solid #6366f1; }
            table { width: 100%; border-collapse: collapse; table-layout: fixed; }
            th { text-align: left; background: #6366f1; color: white; padding: 12px; font-size: 0.75rem; text-transform: uppercase; }
            td { padding: 12px; border-bottom: 1px solid #f1f5f9; font-size: 0.9rem; vertical-align: top; word-wrap: break-word; }
            .col-id { width: 15%; } .col-sev { width: 10%; } .col-title { width: 25%; } .col-cwe { width: 15%; } .col-off { width: 10%; } .col-ev { width: 25%; }
            .Critical { color: #b91c1c; background: #fee2e2; padding: 3px 8px; border-radius: 5px; font-weight: bold; border: 1px solid #fecaca; }
            .High { color: #9a3412; background: #ffedd5; padding: 3px 8px; border-radius: 5px; font-weight: bold; border: 1px solid #fed7aa; }
            .Medium { color: #854d0e; background: #fef9c3; padding: 3px 8px; border-radius: 5px; font-weight: bold; border: 1px solid #fef08a; }
            .Low { color: #1e3a8a; background: #dbeafe; padding: 3px 8px; border-radius: 5px; font-weight: bold; border: 1px solid #bfdbfe; }
            .Info { color: #065f46; background: #d1fae5; padding: 3px 8px; border-radius: 5px; font-weight: bold; border: 1px solid #a7f3d0; }
            code { background: #f1f5f9; color: #475569; padding: 2px 5px; border-radius: 4px; font-family: monospace; font-size: 0.85em; }
        </style>
        """

        script = """
        <script>
            function filterBySeverity(severity) {
                document.querySelectorAll('.f-btn').forEach(btn => btn.classList.remove('active'));
                event.target.classList.add('active');
                const rows = document.querySelectorAll('.finding-row');
                rows.forEach(row => {
                    if (severity === 'All' || row.dataset.severity === severity) {
                        row.style.display = '';
                    } else {
                        row.style.display = 'none';
                    }
                });
            }
        </script>
        """

        html_start = f"""
        <html><head><meta charset="utf-8"><title>FirmLens Audit Report</title>{css}{script}</head><body><div class='container'>
            <div class='header-card'>
                <h1>FirmLens Security Analysis Framework</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <div class='filter-row'>
                    <button class='f-btn active' onclick="filterBySeverity('All')">All Findings</button>
                    <button class='f-btn' onclick="filterBySeverity('Critical')">Critical</button>
                    <button class='f-btn' onclick="filterBySeverity('High')">High</button>
                    <button class='f-btn' onclick="filterBySeverity('Medium')">Medium</button>
                </div>
            </div>
        """

        content = ""
        for analyzer, findings in results.items():
            if not findings: continue
            content += f"<div class='card'><h2>{analyzer}</h2>"
            content += "<table><tr><th class='col-id'>ID</th><th class='col-sev'>Severity</th><th class='col-title'>Title</th><th class='col-cwe'>CWEs</th><th class='col-off'>Offset</th><th class='col-ev'>Evidence</th></tr>"
            for f in findings:
                try:
                    f_id, severity, title, cwes_list, evidence, offset = self._extract_fields(f)
                    cwes_str = ", ".join(cwes_list) if cwes_list else "-"
                    off_str = hex(offset) if isinstance(offset, int) else str(offset)
                    
                    # Defend HTML layout from breaking on raw payload binary string bytes
                    escaped_evidence = html.escape(str(evidence or '-'))
                    escaped_title = html.escape(str(title or ''))

                    content += f"""
                    <tr class='finding-row' data-severity='{severity}'>
                        <td>{f_id}</td>
                        <td><span class='{severity}'>{severity}</span></td>
                        <td>{escaped_title}</td>
                        <td>{cwes_str}</td>
                        <td><code>{off_str}</code></td>
                        <td><code>{escaped_evidence}</code></td>
                    </tr>"""
                except Exception:
                    pass
            content += "</table></div>"

        with open(path, "w", encoding="utf-8") as f:
            f.write(html_start + content + "</div></body></html>")
        self.console.print(f"[success]✔ Professional HTML Report compiled and saved successfully to:[/success] {path}")