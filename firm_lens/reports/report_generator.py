import os
import json
from datetime import datetime
from typing import Dict, List
from rich.console import Console
from rich.table import Table
from rich.theme import Theme
from firm_lens.utils.findings import Finding

class ReportGenerator:
    """
    Industrial-grade Report Orchestrator.
    Generates interactive security analysis reports with aligned tables and offset data.
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

    def generate(self, results: Dict[str, List[Finding]], fmt: str = "terminal", explicit_path: str = None):
        """Orchestrates report generation for requested formats."""
        self._generate_terminal(results)

        formats_to_gen = ["json", "html"] if fmt == "all" else [fmt]
        
        for f in formats_to_gen:
            if f == "terminal":
                continue
                
            target_path = self._resolve_path(explicit_path, f)
            
            if f == "json":
                self._generate_json(results, target_path)
            elif f == "html":
                self._generate_html(results, target_path)

    def _resolve_path(self, explicit_path: str, extension: str) -> str:
        """Ensures correct file extensions and timestamped directories."""
        if explicit_path:
            if not explicit_path.lower().endswith(f".{extension}"):
                return f"{explicit_path}.{extension}"
            return explicit_path
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        session_dir = os.path.join(self.base_dir, f"audit_{timestamp}")
        os.makedirs(session_dir, exist_ok=True)
        return os.path.join(session_dir, f"security_report.{extension}")

    def _get_severity_color(self, severity: str) -> str:
        """Maps severity levels to Rich terminal colors."""
        mapping = {
            "Critical": "bold red",
            "High": "red",
            "Medium": "yellow",
            "Low": "blue",
            "Info": "cyan"
        }
        return mapping.get(severity, "white")

    def _generate_terminal(self, results: Dict[str, List[Finding]]):
        """Generates the high-contrast terminal report with full evidence."""
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
                sev_color = self._get_severity_color(f.severity)
                cwes = ", ".join(f.cwes) if f.cwes else "-"
                table.add_row(analyzer, f.id, f"[{sev_color}]{f.severity}[/]", f.title, cwes)
        
        self.console.print(table)

        self.console.print("\n[bold underline title]Detailed Evidence[/bold underline title]\n")
        for analyzer, findings in results.items():
            for f in findings:
                sev_color = self._get_severity_color(f.severity)
                off_str = hex(f.offset) if isinstance(f.offset, int) else str(f.offset)
                self.console.print(f"[cyan]{analyzer}[/cyan] → [bold]{f.id}[/bold]")
                self.console.print(f"  • Title: {f.title}")
                self.console.print(f"  • Severity: [{sev_color}]{f.severity}[/]")
                self.console.print(f"  • CWEs: {', '.join(f.cwes) if f.cwes else '-'}")
                self.console.print(f"  • Evidence: [italic]{f.evidence or '-'}[/italic]")
                self.console.print(f"  • Offset: {off_str}")
                self.console.print("")

    def _generate_json(self, results: Dict[str, List[Finding]], path: str):
        """Saves findings in machine-readable JSON format with offsets."""
        data = {
            "audit_info": {"tool": "FirmLens", "timestamp": datetime.now().isoformat()},
            "findings": []
        }
        for analyzer, findings in results.items():
            for f in findings:
                f_dict = f.to_dict()
                # Ensure offset is hex-encoded for JSON readability
                if isinstance(f.offset, int):
                    f_dict["offset"] = hex(f.offset)
                f_dict["analyzer"] = analyzer
                data["findings"].append(f_dict)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        self.console.print(f"[success]✔ JSON report saved:[/success] {path}")

    def _generate_html(self, results: Dict[str, List[Finding]], path: str):
        """Generates a professional HTML report with straight columns and smart filtering."""
        css = """
        <style>
            body { font-family: 'Inter', -apple-system, sans-serif; background: #f8fafc; color: #334155; padding: 50px; }
            .container { max-width: 1200px; margin: auto; }
            .header-card { background: #1e293b; color: white; border-radius: 12px; padding: 30px; margin-bottom: 25px; }
            .filter-row { margin-top: 20px; display: flex; gap: 12px; }
            .f-btn { background: #334155; border: 1px solid #475569; color: #cbd5e1; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 0.85rem; }
            .f-btn.active { background: #6366f1; color: white; border-color: #6366f1; font-weight: bold; }
            .card { background: white; border-radius: 12px; padding: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); margin-bottom: 25px; border-left: 5px solid #6366f1; }
            
            /* FIXED TABLE ALIGNMENT */
            table { width: 100%; border-collapse: collapse; table-layout: fixed; }
            th { text-align: left; background: #6366f1; color: white; padding: 12px; font-size: 0.75rem; text-transform: uppercase; }
            td { padding: 12px; border-bottom: 1px solid #f1f5f9; font-size: 0.9rem; vertical-align: top; word-wrap: break-word; }
            
            /* Column Width Definitions */
            .col-id { width: 15%; }
            .col-sev { width: 10%; }
            .col-title { width: 25%; }
            .col-cwe { width: 15%; }
            .col-off { width: 10%; }
            .col-ev { width: 25%; }

            .Critical { color: #b91c1c; background: #fee2e2; padding: 3px 8px; border-radius: 5px; font-weight: bold; border: 1px solid #fecaca; }
            .High { color: #9a3412; background: #ffedd5; padding: 3px 8px; border-radius: 5px; font-weight: bold; border: 1px solid #fed7aa; }
            .Medium { color: #854d0e; background: #fef9c3; padding: 3px 8px; border-radius: 5px; font-weight: bold; border: 1px solid #fef08a; }
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
                        row.classList.remove('hidden-row');
                        row.style.display = '';
                    } else {
                        row.classList.add('hidden-row');
                        row.style.display = 'none';
                    }
                });
                document.querySelectorAll('.card').forEach(card => {
                    const visibleRows = card.querySelectorAll('.finding-row:not(.hidden-row)');
                    card.style.display = (visibleRows.length > 0) ? '' : 'none';
                });
            }
        </script>
        """

        html_start = f"""
        <html><head>{css}{script}</head><body><div class='container'>
            <div class='header-card'>
                <h1>FirmLens Security Analysis Report</h1>
                <p class='ts'>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
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
                cwes = ", ".join(f.cwes) if f.cwes else "-"
                off_str = hex(f.offset) if isinstance(f.offset, int) else str(f.offset)
                content += f"""
                <tr class='finding-row' data-severity='{f.severity}'>
                    <td>{f.id}</td>
                    <td><span class='{f.severity}'>{f.severity}</span></td>
                    <td>{f.title}</td>
                    <td>{cwes}</td>
                    <td><code>{off_str}</code></td>
                    <td><code>{f.evidence or '-'}</code></td>
                </tr>"""
            content += "</table></div>"

        with open(path, "w", encoding="utf-8") as f:
            f.write(html_start + content + "</div></body></html>")
        self.console.print(f"[success]✔ Professional Report saved:[/success] {path}")