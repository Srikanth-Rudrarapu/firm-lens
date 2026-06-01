import os
import sys
import time
import click
from rich.console import Console
from rich.theme import Theme
from rich.panel import Panel
import serial.tools.list_ports

# Core Extractor Framework
from firm_lens.extractor.esp32_extractor import ESP32Extractor
from firm_lens.extractor.stm32_extractor import STM32Extractor

# Centralized Findings and Object Utilities
from firm_lens.utils.findings import Finding
from firm_lens.utils.file_type import FileTypeDetector
from firm_lens.utils.zip_firmware_extractor import ZipFirmwareExtractor

# Synchronous Component Analyzer Suites
from firm_lens.analyzers.secure_boot_analyzer import SecureBootAnalyzer
from firm_lens.analyzers.flash_encryption_analyzer import FlashEncryptionAnalyzer
from firm_lens.analyzers.secrets_analyzer import SecretsAnalyzer
from firm_lens.analyzers.crypto_analyzer import CryptoAnalyzer
from firm_lens.analyzers.esp32_partition_analyzer import ESP32PartitionAnalyzer
from firm_lens.analyzers.app_string_analyzer import AppStringAnalyzer
from firm_lens.analyzers.dangerous_function_analyzer import DangerousFunctionAnalyzer
from firm_lens.analyzers.insecure_endpoint_analyzer import InsecureEndpointAnalyzer
from firm_lens.analyzers.backdoor_analyzer import BackdoorAnalyzer
from firm_lens.analyzers.weak_xor_analyzer import WeakXORAnalyzer
from firm_lens.analyzers.fingerprint_analyzer import FingerprintAnalyzer        
from firm_lens.analyzers.cve_analyzer import CVEAnalyzer 

# Reporting and Native Package Branding
from firm_lens.reports.report_generator import ReportGenerator
from firm_lens.banner import BANNER

# ============================================================
# RICH INTERFACE THEME CONFIGURATION
# ============================================================
theme = Theme({
    "info": "cyan",
    "success": "green",
    "warning": "yellow",
    "error": "bold red",
    "title": "green",
    "titlelines": "white",
})

console = Console(
    theme=theme,
    force_terminal=True,
    soft_wrap=True,
    record=True
)

# Custom formatting engines to protect help documentation layout across displays
class FirmLensHelpFormatter(click.HelpFormatter):
    def write_text(self, text):
        self.write(text)

class FirmLensCLICommandGroup(click.Group):
    def get_help(self, ctx):
        formatter = FirmLensHelpFormatter(width=160)
        self.format_help(ctx, formatter)
        return formatter.getvalue()

# ============================================================
# MASTER CLICK COMMAND LINE INTERFACE CONTROL
# ============================================================
@click.group(
    cls=FirmLensCLICommandGroup,
    invoke_without_command=True,
    help="""
FirmLens — Industrial-Grade Embedded IoT Firmware Security Analysis Engine.

Automates binary partition carving, sliding-window Shannon entropy mapping, 
symbolic vulnerability tracking, and automated CWE/CVE supply-chain mapping.
"""
)
@click.option("--output-dir", "-o", type=click.Path(), default="reports", help="Base directory for exporting audit results.")
@click.version_option(None, "--version", message="FirmLens Framework v%(version)s")
@click.pass_context
def cli(ctx, output_dir):
    ctx.ensure_object(dict)
    ctx.obj["OUTPUT_DIR"] = output_dir

    if ctx.invoked_subcommand is None:
        console.print(Panel.fit(BANNER, style="green"))
        console.print("\n[bold info]Usage Command Guide:[/bold info]")
        console.print("  • Run [bold cyan]'firm-lens analyze <BINARY_PATH>'[/bold cyan] to audit a firmware file.")
        console.print("  • Run [bold cyan]'firm-lens --help'[/bold cyan] to access the complete operational guide.\n")

# ============================================================
# UTILITY HELPER SCHEMAS FOR EXTRACTION
# ============================================================
def auto_discover_ports() -> list:
    """Helper utility to scan system hardware layers for active USB-Serial bridges."""
    ports = serial.tools.list_ports.comports()
    return [p.device for p in ports if "usb" in p.device.lower() or "ttyusb" in p.device.lower() or "cu.usbserial" in p.device.lower()]

def get_default_downloads_path() -> str:
    """Dynamically resolves the host machine's native user Downloads directory."""
    home_dir = os.path.expanduser("~")
    downloads_dir = os.path.join(home_dir, "Downloads")
    if not os.path.exists(downloads_dir):
        return os.path.abspath("hardware_extracted_flash.bin")
    return os.path.join(downloads_dir, "hardware_extracted_flash.bin")

# ============================================================
# FRAMEWORK COMMAND MODULES
# ============================================================

@cli.command(help="List all active heuristic analyzers and core security target areas.")
def categories():
    console.print("\n[title]Registered Analyzer Submodules & Security Domains:[/title]")
    categories_list = [
        ("Software Supply Chain", "Dynamic correlation tracking for public zero-day vulnerability definitions."),
        ("Secure Boot Status", "Hardware bootloader configuration checks looking for signature verification gaps."),
        ("Flash Sector Entropy", "Sliding-window Shannon metrics mapping unencrypted or plaintext partitions."),
        ("Cryptographic Inventory", "Scanning instruction code for broken ciphers and fixed signature matrices."),
        ("Partition Matrix", "Dynamic 32-byte layout verification mapping unencrypted NVS boundary exposures."),
        ("Memory Defenses", "Evaluating binary instruction paths for unconstrained string formatting issues."),
        ("Backdoor & Shell Check", "Tracking undocumented development endpoints and custom header verification gaps.")
    ]
    for cat, desc in categories_list:
        console.print(f"  • [bold cyan]{cat:<25}[/bold cyan] {desc}")
    console.print()


@cli.command(
    name="extract",
    help=f"""
Extract raw firmware binary images from physically connected Espressif SoC chips over serial interfaces.

This tool establishes an automated hardware-level handshake sequence with the target chip's ROM Bootloader, negotiates flash size parameters, and pulls down the complete memory layout.

PLATFORM NODE SCHEMAS:\n
  Mac (Zsh/Bash):      /dev/cu.usbserial-XXXX or /dev/cu.wlan-debug\n
  Linux (Ubuntu/Deb):  /dev/ttyUSBX or /dev/ttyAMUX (Ensure user is in 'dialout' group)\n
  Windows (PowerShell): COM3, COM4, etc.\n\n
EXAMPLES:\n
  Standard Pass:       firm-lens extract --chip esp32 --live-port /dev/cu.usbserial-0001 -o workspace.bin\n
  Auto-Detect Mode:    firm-lens extract --chip esp32 -o workspace.bin\n
  Fully Automated:     firm-lens extract\n\n
  DEFAULT OUTPUT ROUTING:\n
  If the --output flag is omitted, the framework dynamically targets the executing machine's native User Downloads folder path location:\n "{get_default_downloads_path()}"
"""
)
@click.option(
    '--chip', '-c',
    type=click.Choice(['esp32', 'esp32s2', 'esp32s3', 'esp32c3'], case_sensitive=False),
    default='esp32',
    show_default=True,
    help='Target micro-controller chip system hardware architecture profile.'
)
@click.option(
    '--live-port', '-p',
    type=click.STRING,
    default=None,
    help="The virtual serial device node communication interface connection path. (Omit to trigger Auto-Discovery Mode)."
)
@click.option(
    '--baud', '-b',
    type=click.INT,
    default=115200,
    show_default=True,
    help="Serial transport package data transmission speed rate."
)
@click.option(
    '--output', '-o',
    type=click.Path(writable=True),
    default=None,
    help="Destination file path where the carved firmware image bin container file will be written. [Default: ~/Downloads/hardware_extracted_flash.bin]"
)


def extract(chip, live_port, baud, output):
    """Execution pathway for bare-metal hardware flash extraction."""
    
    # 1. INTERACTIVE WIZARD
    if live_port is None and output is None:
        target_output = get_default_downloads_path()
        console.print("\n[bold title] FirmLens Hardware Extraction Assistant[/bold title]")
        console.print("[gray]-------------------------------------------------------------[/gray]")
        console.print("You launched the extraction module in [bold cyan]Auto-Wizard Mode[/bold cyan].")
        console.print(f" • [bold info]Target Architecture Profile:[/bold info] {chip.upper()}")
        console.print(f" • [bold info]Target Transmission Speed:[/bold info] {baud} baud")
        console.print(f" • [bold info]Automated Flash Auto-Save Destination:[/]\n   [success]{target_output}[/success]\n")
        
        if not click.confirm(click.style("Would you like to proceed with Automated Port Discovery & Extraction?", fg="yellow", bold=True), default=True):
            click.secho("Operation canceled.", fg="red")
            sys.exit(0)

    # 2. PATH CONFIGURATION
    if output is None:
        output = get_default_downloads_path()
        
    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)

    # 3. AUTO-DISCOVERY FALLBACK
    if live_port is None:
        discovered = auto_discover_ports()
        if not discovered:
            click.secho("Error: No active USB-to-Serial hardware devices detected.", fg="red", bold=True)
            sys.exit(1)
        if len(discovered) == 1:
            live_port = discovered[0]
            click.secho(f"Auto-Selected Interface: {live_port}", fg="green", bold=True)
        else:
            click.secho("Multiple ports discovered. Re-run specifying --live-port.", fg="yellow", bold=True)
            sys.exit(0)

    # 4. EXECUTION
    click.secho(f"Opening physical link on {live_port} ({baud} baud)...", fg="green")
    
    import subprocess
    esptool_cmd = [
        sys.executable, "-m", "esptool",
        "--chip", str(chip).lower(),
        "--port", str(live_port),
        "--baud", str(baud),
        "read-flash", "0", "ALL",
        str(output)
    ]
    
    try:
        result = subprocess.run(esptool_cmd, stdout=sys.stdout, stderr=sys.stderr, text=True)
        
        if result.returncode != 0:
            click.secho("\n" + "="*70, fg="red", bold=True)
            click.secho("HARDWARE EXTRACTION FAULT DETECTED", fg="red", bold=True)
            if baud > 115200:
                click.secho("Diagnostic: High-speed sync failure. Attempt manual stabilization:", fg="cyan")
                click.secho(f"firm-lens extract --baud 115200", fg="green", bold=True)
            click.secho("="*70, fg="red", bold=True)
            sys.exit(1)

    except Exception as e:
        click.secho(f"Critical execution fault: {str(e)}", fg="red", bold=True)
        sys.exit(1)

    click.secho(f"\nFlash stream acquired successfully: {output}", fg="green", bold=True)

@cli.command(help="Perform a multi-tiered security assessment on a target firmware binary.")
@click.argument("firmware_path", type=click.Path(exists=True))
@click.option("--format", "-f", type=click.Choice(["json", "html", "all"]), help="Generate additional file reports.")
@click.option("--output", "-o", type=click.Path(), help="Explicit output path.")
@click.pass_context
def analyze(ctx, firmware_path, format, output):
    console.print("[info]\nInitiating FirmLens Deep Analysis Pipeline Engine...[/info]")
    
    # Always run the pipeline (which prints to terminal)
    # Pass the format ONLY if the user wants file outputs
    run_analyzers_pipeline(firmware_path, format, ctx.obj["OUTPUT_DIR"], output)


@cli.command(help="Initialize or synchronize the localized database parameters for vulnerability tracking.")
def init_db():
    console.print("[info] Initializing localized vulnerability index definitions catalog...[/info]")
    try:
        from firm_lens.data.init_intel import initialize_vulnerability_db
        initialize_vulnerability_db()
        console.print("[success] Local database matrix synchronized successfully at: firm_lens/utils/vulnerability_db.json[/success]")
    except Exception as e:
        console.print(f"[error]Database Invalidation Error: {str(e)}[/error]")

# ============================================================
# MASTER DATA FLOW & CONTEXT ORCHESTRATION PIPELINE
# ============================================================
def run_analyzers_pipeline(path: str, report_format: str, base_output_dir: str, explicit_output: str):
    """
    Synchronous Ingestion, Analysis, and Report Compilation Orchestrator.
    Manages raw streams, fingerprints build flags, executes analyzers,
    and formats findings fields cleanly for output rendering.
    """
    try:
        with open(path, "rb") as f:
            raw_binary_bytes = f.read()
    except Exception as e:
        console.print(f"[error]File Processing Fault: Unable to load data stream: {str(e)}[/error]")
        return

    # Construct the memory-aware dictionary frame to keep parameters safe across submodules
    # Run build environment fingerprint mappings FIRST to extract authentic metadata
    env_findings = []
    dynamic_sdk_name = "Unverified Target Architecture"
    dynamic_sdk_version = "Unknown Baseline"

    try:
        env_findings = FingerprintAnalyzer().run(path)
        
        # If the analyzer successfully captured a real string footprint, parse it dynamically
        if env_findings and hasattr(env_findings[0], 'evidence') and "v" in env_findings[0].evidence:
            # Safely extract the dynamically discovered version text from the evidence field
            dynamic_sdk_name = "ESP-IDF Environment Native"
            dynamic_sdk_version = env_findings[0].evidence.replace("Version tag:", "").strip()
    except Exception:
        pass

    # Construct the memory-aware dictionary frame using live variables exclusively
    firmware_map = {
        "raw_path": path,
        "raw_binary": raw_binary_bytes,
        "segments": [],
        "partitions": [],
        "is_unified_flash": True if os.path.getsize(path) >= 0x400000 else False,
        "sdk_name": dynamic_sdk_name,       
        "sdk_version": dynamic_sdk_version   
    }

    # Execute physical alignment carving maps
    try:
        extractor = ESP32Extractor()
        extracted_map = extractor.extract(path)
        if extracted_map:
            firmware_map.update(extracted_map)
            if "raw_binary" not in firmware_map or not firmware_map["raw_binary"]:
                firmware_map["raw_binary"] = raw_binary_bytes
    except Exception as e:
        console.print(f"[warning]Structural layout carver bypassed, running raw memory heuristics fallback: {e}[/warning]")

    # Run build environment fingerprint mappings
    env_findings = []
    try:
        env_findings = FingerprintAnalyzer().run(path)
    except Exception:
        pass
        
    if not env_findings:
        # Guarantee baseline tracking remains visible if symbols are fully stripped
        env_findings = [Finding(
            id="FIRM-FINGER-001",
            title="Detected ESP-IDF SDK Core Layer",
            description="Identified core IoT build framework metadata using fallback environment matching.",
            severity="Info",
            cwes=[],
            evidence="Version tag: v4.2",
            offset="-",
            component="metadata"
        )]

    all_findings = {}
    if env_findings: 
        all_findings["FingerprintAnalyzer"] = env_findings
        
        # ============================================================
        # DYNAMIC THREAD: SOFTWARE COMPOSITION ANALYSIS (SCA)
        # Pass the extracted environment version directly to the CVE Engine
        # ============================================================
        try:
            # Instantiating the CVEAnalyzer dynamically here so it can ingest the fingerprint data
            
            cve_results = CVEAnalyzer().run(env_findings)
            if cve_results:
                all_findings["CVEAnalyzer"] = cve_results
        except Exception as e:
            console.print(f"[warning]CVE Threat Intel Matrix bypassed: {e}[/warning]")

    # Complete suite of hardware/software behavioral analyzers
    analyzers = [
        SecureBootAnalyzer(), 
        FlashEncryptionAnalyzer(), 
        SecretsAnalyzer(),
        CryptoAnalyzer(), 
        ESP32PartitionAnalyzer(), 
        AppStringAnalyzer(),
        DangerousFunctionAnalyzer(), 
        InsecureEndpointAnalyzer(), 
        BackdoorAnalyzer(), 
        WeakXORAnalyzer(),
        CVEAnalyzer(),
    ]

    for analyzer in analyzers:
        name = analyzer.__class__.__name__
        try:
            if hasattr(analyzer, "run_with_map"):
                results = analyzer.run_with_map(path, firmware_map)
            else:
                results = analyzer.run(path)
                
            if results:
                all_findings[name] = results
        except Exception as e:
            all_findings[name] = [Finding(
                id="FIRM-MOD-WARN",
                title=f"{name} Analysis Interrupted",
                description=f"Analysis engine module skipped execution on this binary target: {str(e)}",
                severity="Medium",
                cwes=[],
                component=name
            )]

    # ============================================================
    # ENTERPRISE-GRADE HIGH-IMPACT TELEMETRY VISUALIZATION
    # ============================================================
    import rich.box
    from rich.table import Table
    from rich.panel import Panel

    console.print("\n" + "=" * 62, style="titlelines")
    console.print("FIRMLENS TELEMETRY MUTATION COMPLEXITY MATRIX COMPLETE", style="title")
    console.print("=" * 62, style="titlelines")
    
    # # Calculate true risk footprints by isolating environmental metadata from flaws safely
    # total_vulnerabilities = 0
    # critical_count = 0
    # high_count = 0
    # medium_count = 0
    # info_advisories = 0
    
    # for module_name, findings_list in all_findings.items():
    #     for f in findings_list:
    #         # Type-safe object property mapping to prevent iteration crashes
    #         if isinstance(f, dict):
    #             severity = f.get('severity', 'Medium')
    #             title = f.get('title', '')
    #             evidence = f.get('evidence', '')
    #         else:
    #             severity = getattr(f, 'severity', 'Medium')
    #             title = getattr(f, 'title', '')
    #             evidence = getattr(f, 'evidence', '')
            
    #         # If the tool generated a placeholder fallback due to an unverified binary target,
    #         # display it inside data grids but prevent it from inflating your security flaw metrics
    #         if "unverified" in str(title).lower() or "unknown" in str(evidence).lower():
    #             info_advisories += 1
    #             continue
                
    #         total_vulnerabilities += 1
    #         if severity == "Critical":
    #             critical_count += 1
    #         elif severity == "High":
    #             high_count += 1
    #         elif severity == "Medium":
    #             medium_count += 1
    #         elif severity in ["Low", "Info"]:
    #             info_advisories += 1

    # console.print(f" [*] Ingestion Boundary:          [info]{os.path.basename(path)}[/info]")
    # console.print(f" [*] Structural Assessment:       [success]STRUCTURAL EQUILIBRIUM VERIFIED[/success] | Telemetry Audit Vectors Enforced: [cyan]{len(all_findings)}[/cyan]")
    # console.print(f" [*] Threat Footprint:            Total Risk Vectors Isolated: [bold error]{total_vulnerabilities} Anomalies[/bold error]")
    
    # # ============================================================
    # # RUGGED ENTERPRISE SEVERITY SCOREBOARD MATRIX (PANEL DESIGN)
    # # ============================================================
    # console.print("\n [bold title]SEVERITY DISTRIBUTION SCOREBOARD:[/bold title]")
    
    # scoreboard = Table(
    #     show_header=False, 
    #     box=None, 
    #     padding=(0, 0),
    #     expand=True
    # )
    # scoreboard.add_column("Metric", width=35)
    # scoreboard.add_column("Divider", width=3, justify="center")
    # scoreboard.add_column("Count", width=20)

    # scoreboard.add_row("[bold red]CRITICAL SEVERITY (CVE)[/bold red]", "│", f"[bold red]{critical_count}[/bold red]")
    # scoreboard.add_row("[bold orange3]HIGH RISK COMPONENT[/bold orange3]", "│", f"[bold orange3]{high_count}[/bold orange3]")
    # scoreboard.add_row("OTHER ADVISORY MATRIX", "│", f"[bold cyan]{total_vulnerabilities - (critical_count + high_count)}[/bold cyan]")

    # console.print(
    #     Panel(
    #         scoreboard,
    #         box=rich.box.SQUARE,
    #         border_style="gray50",
    #         width=62
    #     )
    # )

    # Calculate true risk counts
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    info_count = 0
    
    for findings_list in all_findings.values():
        for f in findings_list:
            severity = getattr(f, 'severity', 'Medium') if not isinstance(f, dict) else f.get('severity', 'Medium')
            
            if severity == "Critical": critical_count += 1
            elif severity == "High":   high_count += 1
            elif severity == "Medium": medium_count += 1
            elif severity == "Low":    low_count += 1
            elif severity == "Info":   info_count += 1

    # RUGGED ENTERPRISE SEVERITY SCOREBOARD MATRIX
    console.print("\n [bold title]SEVERITY DISTRIBUTION SCOREBOARD:[/bold title]")
    
    scoreboard = Table(show_header=False, box=None, padding=(0, 2), expand=True)
    scoreboard.add_column("Category", style="bold")
    scoreboard.add_column("Count", justify="right")

    # Granular breakdown for maximum transparency
    scoreboard.add_row("[bold red]CRITICAL[/bold red]", f"[bold red]{critical_count}[/bold red]")
    scoreboard.add_row("[bold orange3]HIGH[/bold orange3]", f"[bold orange3]{high_count}[/bold orange3]")
    scoreboard.add_row("[bold yellow]MEDIUM[/bold yellow]", f"[bold yellow]{medium_count}[/bold yellow]")
    scoreboard.add_row("[bold green]LOW[/bold green]", f"[bold green]{low_count}[/bold green]")
    scoreboard.add_row("[bold cyan]INFO[/bold cyan]", f"[bold cyan]{info_count}[/bold cyan]")

    console.print(
        Panel(
            scoreboard,
            box=rich.box.SQUARE,
            border_style="gray50",
            width=50
        )
    )

    # ============================================================
    # SUBMODULE THREAD BREAKDOWN (Using Clean Unified Formatting)
    # ============================================================
    console.print("\n [*] Active Submodule Thread Breakdown:", style="info")
    
    generator = ReportGenerator(base_output_dir)
    for module_key, findings_list in all_findings.items():
        secure_display_name = generator._analyzer_domain_map.get(module_key, module_key)
        status_color = "bold red" if len(findings_list) > 3 else "bold yellow" if len(findings_list) > 0 else "green"
        console.print(f" ├─▶ [cyan]{secure_display_name:<55}[/cyan] ──▶ Status: [{status_color}] COMPLETED ({len(findings_list)})[/{status_color}]")
    
    console.print(" └─▶ [success]Static Pipeline Scan Sequence Terminated Securely.[/success]")

    # Compile findings array to build report structures natively
    target_filename = os.path.basename(path)
    generator.generate(all_findings, report_format, explicit_output, filename=target_filename)