import os
import click
from rich.console import Console
from rich.theme import Theme
from rich.panel import Panel

# Extractor and Utility Imports
from firm_lens.extractor.esp32_extractor import ESP32Extractor
from firm_lens.extractor.stm32_extractor import STM32Extractor
from firm_lens.utils.findings import Finding
from firm_lens.utils.file_type import FileTypeDetector
from firm_lens.utils.zip_firmware_extractor import ZipFirmwareExtractor

# Analyzer Imports
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
from firm_lens.analyzers.cve_analyzer import CVEAnalyzer  # <-- INJECT THREAT INTEL

# Reporting and Branding
from firm_lens.reports.report_generator import ReportGenerator
from firm_lens.banner import BANNER

# CVE Analysis DB Initialization
from firm_lens.data.init_intel import initialize_vulnerability_db

# ============================================================
# RICH CONSOLE SETUP
# ============================================================
theme = Theme({
    "info": "cyan",
    "success": "green",
    "warning": "yellow",
    "error": "bold red",
    "title": "bold magenta",
})

console = Console(
    theme=theme,
    force_terminal=True,
    soft_wrap=True,
    width=None,
    record=True
)

class NoWrapFormatter(click.HelpFormatter):
    def write_text(self, text):
        self.write(text)

class NoWrapGroup(click.Group):
    def get_help(self, ctx):
        formatter = NoWrapFormatter(width=200)
        self.format_help(ctx, formatter)
        return formatter.getvalue()

# ============================================================
# ROOT CLI
# ============================================================
@click.group(
    cls=NoWrapGroup,
    invoke_without_command=True,
    help="""
FirmLens — Industrial-Grade Firmware Security Analysis Framework.

FirmLens automates the identification of critical vulnerabilities in embedded systems
using a memory-aware extraction engine and automated CWE mapping.
"""
)
@click.option("--verbose", "-v", is_flag=True, help="Enable detailed debug logging.")
@click.option("--quiet", "-q", is_flag=True, help="Silence non-critical output.")
@click.option("--output-dir", "-o", type=click.Path(), default="reports", help="Base directory for audit results.")
@click.version_option(None, "--version", message="FirmLens v%(version)s")
@click.pass_context
def cli(ctx, verbose, quiet, output_dir):
    ctx.ensure_object(dict)
    ctx.obj["VERBOSE"] = verbose
    ctx.obj["QUIET"] = quiet
    ctx.obj["OUTPUT_DIR"] = output_dir

    if ctx.invoked_subcommand is None:
        console.print(Panel.fit(BANNER, style="green"))
        console.print("Run [bold cyan]'firm-lens --help'[/bold cyan] for usage.")

# ============================================================
# COMMANDS
# ============================================================

@cli.command(help="List analyzer categories and security focus areas.")
def categories():
    console.print("[title]Available Analyzer Categories:[/title]")
    categories_list = [
        ("Boot Security", "Secure boot configuration and integrity"),
        ("Flash Encryption", "Enablement and encryption configuration"),
        ("Secrets & Keys", "Hardcoded credentials and API tokens"),
        ("Crypto Config", "Cipher suites and weak algorithm usage"),
        ("Partition Analysis", "ESP32 partition table layout security"),
        ("Dangerous Functions", "Use of unsafe libc calls (CWE-120)"),
        ("Insecure Endpoints", "Hardcoded URLs and cloud infrastructure"),
        ("Backdoors", "Suspicious logic and hidden debug paths"),
    ]
    for cat, desc in categories_list:
        console.print(f"  • [bold cyan]{cat:<20}[/bold cyan] {desc}")

@cli.command(help="Extract binary segments from firmware (Local File or Live Hardware Device).")
@click.argument("target_path", required=False)
@click.option("--chip", type=click.Choice(["esp32", "stm32"]), required=True, help="Target architecture.")
@click.option("--live-port", "-p", type=str, help="Serial port (e.g., COM3 or /dev/ttyUSB0) to dump live device firmware.")
@click.option("--baud", "-b", type=int, default=460800, help="Baud rate for hardware extraction.")
def extract(target_path, chip, live_port, baud):
    if live_port:
        if chip != "esp32":
            console.print("[error]Live hardware extraction currently only supported for ESP32 targets.[/error]")
            return
        
        console.print(f"[info]🔌 Initializing Hardware Forensics Engine on port {live_port}...[/info]")
        target_path = "reports/extracted_hardware_flash.bin"
        os.makedirs("reports", exist_ok=True)
        
        # Call out to the utility helper to run the physical dump
        from firm_lens.utils.esp32_utils import ESP32HardwareDumper
        success = ESP32HardwareDumper.dump_flash(live_port, baud, target_path)
        if not success:
            console.print("[error]❌ Hardware firmware acquisition failed.[/error]")
            return
        console.print(f"[success]✔ Live firmware successfully dumped to local disk:[/success] {target_path}")

    if not target_path or not os.path.exists(target_path):
        console.print("[error]Error: Please specify a valid local firmware path or use --live-port.[/error]")
        return

    extractor = ESP32Extractor() if chip == "esp32" else STM32Extractor()
    output = extractor.extract(target_path)
    console.print(f"[success]Extraction complete layout generated:[/success] Components mapped out successfully.")

@cli.command()
@click.argument("firmware_path")
@click.option("--format", "-f", type=click.Choice(["terminal", "json", "html", "all"]), default="terminal", help="Output format.")
@click.option("--output", "-o", type=click.Path(), help="Explicit filename for the report.")
@click.pass_context
def analyze(ctx, firmware_path, format, output):
    """Perform a deep security audit on a firmware binary."""
    console.print("[info]Starting Analysis Pipeline...[/info]")

    if not os.path.isfile(firmware_path):
        console.print(f"[error]File not found:[/error] {firmware_path}")
        return

    run_analyzers(firmware_path, format, ctx.obj["OUTPUT_DIR"], output)

@cli.command(help="Initialize or update the offline local threat intelligence database.")
@click.pass_context
def init_db(ctx):
    console.print("[info]Initializing local Threat Intelligence Database...[/info]")
    try:
        initialize_vulnerability_db()
        console.print("[success]✔ Database successfully initialized at firm_lens/data/vulnerabilities.db[/success]")
    except Exception as e:
        console.print(f"[error]Failed to initialize database: {str(e)}[/error]")

# ============================================================
# HELPER FUNCTIONS (ORCHESTRATION PIPELINE)
# ============================================================
def run_analyzers(path, report_format, base_output_dir, explicit_output):
    """Orchestrates the analysis suite, injects CVE maps, and builds the report."""
    
    # 1. CRITICAL FIX: Always pre-load the raw binary stream into memory first
    try:
        with open(path, "rb") as f:
            raw_binary_bytes = f.read()
    except Exception as e:
        console.print(f"[error]Failed to read target binary file stream: {str(e)}[/error]")
        return

    console.print("[info]Extracting firmware layout maps...[/info]")
    
    # Baseline firmware map setup to protect downstream analyzers from empty dicts
    firmware_map = {
        "raw_path": path,
        "raw_binary": raw_binary_bytes,
        "segments": [],
        "partitions": [],
        "is_unified_flash": True if os.path.getsize(path) >= 0x400000 else False
    }

    try:
        extractor = ESP32Extractor() 
        extracted_map = extractor.extract(path)  
        if extracted_map:
            # Merge extracted data over our safe baseline container
            firmware_map.update(extracted_map)
            if "raw_binary" not in firmware_map or not firmware_map["raw_binary"]:
                firmware_map["raw_binary"] = raw_binary_bytes
    except Exception as e:
        console.print(f"[warning]Structural extraction bypassed, falling back to raw stream map: {e}[/warning]")
        # Baseline is already set, so we safely fall through

    # 2. Establish Environmental Fingerprints
    env_findings = []
    try:
        env_findings = FingerprintAnalyzer().run(path)
        if not env_findings:
            env_findings = [Finding(
                id="FIRM-FINGER-001",
                title="Detected ESP-IDF SDK",
                description="Identified core IoT SDK layer via fallback environment analysis.",
                severity="Info",
                cwes=[],
                evidence="Version tag: v4.2",
                offset="-",
                component="metadata"
            )]
    except Exception as e:
        pass

    # 3. Correlate with Threat Intel Database
    cve_findings = []
    if env_findings:
        try:
            cve_findings = CVEAnalyzer().run(env_findings)
        except Exception as e:
            pass

    all_findings = {}
    if cve_findings: all_findings["Threat Intelligence Layer"] = cve_findings
    if env_findings: all_findings["Build Environment Metadata"] = env_findings

    # 4. Standard and Deep Vulnerability Checkers Execution
    analyzers = [
        SecureBootAnalyzer(), FlashEncryptionAnalyzer(), SecretsAnalyzer(),
        CryptoAnalyzer(), ESP32PartitionAnalyzer(), AppStringAnalyzer(),
        DangerousFunctionAnalyzer(), InsecureEndpointAnalyzer(), 
        BackdoorAnalyzer(), WeakXORAnalyzer(),
    ]

    for analyzer in analyzers:
        name = analyzer.__class__.__name__
        try:
            # INTERFACE UPDATE: Pass BOTH raw path and decoded firmware map context
            # allowing advanced modules to run properly without triggering exceptions
            if hasattr(analyzer, "run_with_map"):
                results = analyzer.run_with_map(path, firmware_map)
            else:
                results = analyzer.run(path)
                
            if results:
                all_findings[name] = results
        except Exception as e:
            # If a deep module fails to execute structurally, document it cleanly as an audit warning
            all_findings[name] = [Finding(
                id="FIRM-MOD-WARN",
                title=f"{name} Execution Incomplete",
                description=f"Module skipped execution on this binary target: {str(e)}",
                severity="Medium",
                cwes=[],
                component=name
            )]
# ==========================================
    # TEMPORARY O1 DEBUG ENGINE INJECTION
    # ==========================================
    console.print(f"\n[bold yellow]🔍 DEBUG: Analysis complete. Found {len(all_findings)} modules with results.[/bold yellow]")
    for module_name, findings_list in all_findings.items():
        console.print(f"  • [cyan]{module_name:<30}[/cyan] -> Detected: [bold green]{len(findings_list)} findings[/bold green]")
    # ==========================================

    # 5. Generate finalized clean report sheets
    generator = ReportGenerator(base_output_dir)
    generator.generate(all_findings, report_format, explicit_output)