import os
import re
import sys
from datetime import datetime
import click
import sqlite3
from rich.console import Console
from rich.theme import Theme
from rich.panel import Panel
import rich.box
from rich.table import Table
import serial.tools.list_ports
from pathlib import Path

# Core Extractor Framework
from firm_lens.extractor.esp32_extractor import ESP32Extractor

# Centralized Findings and Object Utilities
from firm_lens.utils.findings import Finding
from firm_lens.utils.rules_loader import load_centralized_analyzer_rules 

# Synchronous Component Analyzer Suites
from firm_lens.analyzers.secure_boot_analyzer import SecureBootAnalyzer
from firm_lens.analyzers.flash_encryption_analyzer import FlashEncryptionAnalyzer
from firm_lens.analyzers.secrets_analyzer import SecretsAnalyzer
from firm_lens.analyzers.crypto_analyzer import CryptoAnalyzer
from firm_lens.analyzers.esp32_partition_analyzer import ESP32PartitionAnalyzer
from firm_lens.analyzers.dangerous_function_analyzer import DangerousFunctionAnalyzer
from firm_lens.analyzers.insecure_endpoint_analyzer import InsecureEndpointAnalyzer
from firm_lens.analyzers.backdoor_analyzer import BackdoorAnalyzer
from firm_lens.analyzers.weak_xor_analyzer import WeakXORAnalyzer
from firm_lens.analyzers.fingerprint_analyzer import FingerprintAnalyzer        
from firm_lens.analyzers.cve_analyzer import CVEAnalyzer 

# Reporting and Native Package Branding
from firm_lens.reports.report_generator import ReportGenerator
from firm_lens.banner import BANNER

#Dynamic HIL
from firm_lens.dynamic.serial_monitor import FirmLensHILMonitor
from firm_lens.dynamic.fuzzer_uart import UARTFuzzer
from firm_lens.dynamic.crash_parser import CrashParser
from firm_lens.dynamic.fuzzer_wifi import WiFiFuzzer


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

class FirmLensHelpFormatter(click.HelpFormatter):
    def write_text(self, text):
        self.write(text)

class FirmLensCLICommandGroup(click.Group):
    def get_help(self, ctx):
        formatter = FirmLensHelpFormatter(width=160)
        self.format_help(ctx, formatter)
        return formatter.getvalue()

@click.group(
    cls=FirmLensCLICommandGroup,
    invoke_without_command=True,
    help="""
FirmLens — Automated Static, Hardware-Rooted & Dynamic HIL Security Analysis for Bare-Metal ESP32 (Xtensa & RISC-V) Firmware.

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

def auto_discover_ports() -> list:
    ports = serial.tools.list_ports.comports()
    return [p.device for p in ports if "usb" in p.device.lower() or "ttyusb" in p.device.lower() or "cu.usbserial" in p.device.lower()]


def get_default_downloads_path() -> str:
    home_dir = os.path.expanduser("~")
    downloads_dir = os.path.join(home_dir, "Downloads")
    
    # Generate a unique timestamp for the filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    unique_filename = f"hardware_extracted_flash_{timestamp}.bin"
    
    if not os.path.exists(downloads_dir):
        return os.path.abspath(unique_filename)
    return os.path.join(downloads_dir, unique_filename)

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

@cli.command(name="extract", help="Extract raw firmware binary images from physically connected Espressif SoC chips.")
@click.option('--chip', '-c', type=click.Choice(['esp32', 'esp32s2', 'esp32s3', 'esp32c3'], case_sensitive=False), default='esp32', show_default=True)
@click.option('--live-port', '-p', type=click.STRING, default=None)
@click.option('--baud', '-b', type=click.INT, default=115200, show_default=True)
@click.option('--output', '-o', type=click.Path(writable=True), default=None)
def extract(chip, live_port, baud, output):
    if live_port is None and output is None:
        target_output = get_default_downloads_path()
        console.print("\n[bold title] FirmLens Hardware Extraction Assistant[/bold title]")
        console.print("[gray]-------------------------------------------------------------[/gray]")
        if not click.confirm(click.style("Would you like to proceed with Automated Extraction?", fg="yellow", bold=True), default=True):
            sys.exit(0)

    if output is None:
        output = get_default_downloads_path()
        
    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)

    if live_port is None:
        discovered = auto_discover_ports()
        if not discovered:
            click.secho("Error: No active USB-to-Serial hardware devices detected.", fg="red", bold=True)
            sys.exit(1)
        live_port = discovered[0]

    import subprocess
    esptool_cmd = [sys.executable, "-m", "esptool", "--chip", str(chip).lower(), "--port", str(live_port), "--baud", str(baud), "read-flash", "0", "ALL", str(output)]
    try:
        result = subprocess.run(esptool_cmd, stdout=sys.stdout, stderr=sys.stderr, text=True)
        if result.returncode != 0:
            sys.exit(1)
    except Exception as e:
        click.secho(f"Critical execution fault: {str(e)}", fg="red", bold=True)
        sys.exit(1)


# HIL dynamic fuzzing commands
@cli.command(name="dynamic", help="Launch Hardware-in-the-Loop (HIL) dynamic fuzzing against a live ESP32.")
@click.option('--live-port', '-p', type=click.STRING, default=None, help="Serial port for UART monitoring/fuzzing.")
@click.option('--baud', '-b', type=click.INT, default=115200, show_default=True)
@click.option('--target-ip', '-t', type=click.STRING, default=None, help="IP address for Network fuzzing.")
@click.option('--format', '-f', 'report_format', type=click.Choice(['json', 'html', 'all']), default=None, help="Report output format (e.g., html, json).")
@click.option('--output', '-o', type=click.Path(), default=None, help="Directory to save reports. Defaults to Downloads/FirmLens_Reports/Dynamic.")
def dynamic_audit(live_port, baud, target_ip, report_format, output):
    console.print("[info]\nInitiating FirmLens Dynamic HIL Engine...[/info]")
    
    target_name = target_ip.replace('.', '_') if target_ip else "uart_hil"
    base_name = f"dynamic_audit_{target_name}"

    base_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(base_dir, "data", "vulnerabilities.db")

    # Ensure Threat Intel Database Exists Before Scanning
    if not os.path.exists(db_path):
        console.print("\n[warning]Local Threat Intelligence Database not found.[/warning]")
        console.print("[info]FirmLens requires a localized copy of the latest CVE/EPSS mappings to generate accurate reports.[/info]")
        console.print("Please run the following command to initialize and sync the database:")
        console.print("\n    [bold cyan]firm-lens init-db[/bold cyan]\n")
        sys.exit(1)
    
    # 1. Enforce Dynamic subfolder and parse filename vs directory
    if output is None:
        out_dir = os.path.join(os.path.expanduser('~'), 'Downloads', 'FirmLens_Reports', 'Dynamic')
    else:
        if output.endswith(('/', '\\')) or os.path.isdir(output):
            out_dir = output
        else:
            out_path = Path(output)
            out_dir = str(out_path.parent)
            base_name = out_path.name
            
    if not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    
    if live_port is None:
        discovered = auto_discover_ports()
        if not discovered:
            click.secho("Error: No active USB-to-Serial hardware devices detected.", fg="red", bold=True)
            sys.exit(1)
        live_port = discovered[0]

    console.print(f"[success]Hardware locked on {live_port} at {baud} baud.[/success]")
    
    hil_engine = FirmLensHILMonitor(port=live_port, baudrate=baud)
    if not hil_engine.connect():
        sys.exit(1)

    hil_engine.start()

    # Create a professional display name for the report
    display_asset_name = f"Live ESP32 Target ({target_ip})" if target_ip else "Live ESP32 Target (UART Interconnect)"

    try:
        if target_ip:
            console.print(f"[info]Network Target Provided. Engaging Wi-Fi Fuzzer...[/info]")
            fuzzer = WiFiFuzzer(target_ip=target_ip, crash_event=hil_engine.crash_detected)
        else:
            console.print(f"[info]No IP Provided. Engaging Local UART Fuzzer...[/info]")
            fuzzer = UARTFuzzer(hil_engine.serial_conn, hil_engine.crash_detected)
            
        fuzzer.run()
        
        if hil_engine.crash_detected.is_set():
            console.print("\n[bold red]!!! HARDWARE FAULT DETECTED !!![/bold red]")
            
            parser = CrashParser()
            results = parser.parse_log(hil_engine.crash_log)
            
            console.print(f"[error]Vulnerability:[/error] {results.get('cwe', 'CWE-120')}")
            console.print(f"[error]Severity:[/error]      {results.get('severity', 'CRITICAL')}")
            console.print(f"[error]Fault Type:[/error]    {results.get('fault_type', 'Hardware Exception')}")
            console.print(f"[error]Crash Address:[/error] {results.get('instruction_pointer', 'Unknown')}")
            console.print(f"[error]Evidence:[/error]      {results.get('evidence', 'Hardware crash triggered via fuzzing.')}")
            
            dynamic_finding = Finding(
                id="FL-DYN-01",
                title=f"Catastrophic Hardware Fault: {results.get('fault_type', 'Hardware Exception')}",
                cwes=[results.get('cwe', 'CWE-120: Buffer Overflow / CWE-134: Format String')],
                severity=results.get('severity', 'CRITICAL'),
                offset=results.get('instruction_pointer', 'Unknown'),
                evidence=results.get('evidence', 'Hardware crash triggered via fuzzing.')
            )
            dynamic_finding.remediation_blueprint = "Implement strict memory bounds checking. Utilize safe string handling (e.g., strncpy, snprintf) and sanitize all network/serial buffer inputs before passing to execution contexts."
            
            aggregated_findings = {
                "HardwareInTheLoopFuzzer": [dynamic_finding]
            }
            
            generator = ReportGenerator(out_dir)
            generator.generate(aggregated_findings, report_format, out_dir, filename=base_name, asset_name=display_asset_name)

        else:
            console.print("\n[success]Fuzzing complete. Target device remained stable.[/success]")
            
            # --- NEW: GENERATE BASELINE PASSING REPORTS FOR COMPLIANCE PIPELINES ---
            stable_finding = Finding(
                id="FL-HITL-001",  # Maps cleanly to standard internal tokens
                title="Hardware-in-the-Loop Fuzzing Boundary Verified",
                cwes=[],
                severity="Info",
                offset="System Metric Boundary",
                evidence="Dynamic Telemetry Validation: Microcontroller unit smoothly processed input queues without raising runtime register exceptions, memory boundary spikes, or kernel loops."
            )
            # This triggers the light blue "Verification Passport" drawer layout in your HTML report
            stable_finding.remediation_blueprint = "Verification Metric: Continuous testing pipeline milestone achieved. No runtime memory corruption or state engine desynchronization isolated during this execution window."
            
            aggregated_findings = {
                "HardwareInTheLoopFuzzer": [stable_finding]
            }
            
            generator = ReportGenerator(out_dir)
            generator.generate(aggregated_findings, report_format, out_dir, filename=base_name, asset_name=display_asset_name)
            
    except KeyboardInterrupt:
        console.print("\n[warning]Dynamic analysis manually aborted.[/warning]")
    finally:
        hil_engine.stop()


@cli.command(help="Perform a multi-tiered security assessment on a target firmware binary.")
@click.argument("firmware_path", type=click.Path(exists=True))
@click.option("--format", "-f", 'report_format', type=click.Choice(["json", "html", "all"]), default=None, help="Generate additional file reports (e.g., html, json).")
@click.option("--output", "-o", type=click.Path(), default=None, help="Explicit output path or filename. Defaults to Downloads/FirmLens_Reports/Static.")
def analyze(firmware_path, report_format, output):
    console.print("[info]\nInitiating FirmLens Deep Analysis Pipeline Engine...[/info]")
    
    target_filename = os.path.basename(firmware_path)
    base_name = target_filename

    # Ensure Threat Intel Database Exists Before Scanning
    base_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(base_dir, "data", "vulnerabilities.db")
    
    if not os.path.exists(db_path):
        console.print("\n[warning]Local Threat Intelligence Database not found.[/warning]")
        console.print("[info]FirmLens requires a localized copy of the latest CVE/EPSS mappings to generate accurate reports.[/info]")
        console.print("Please run the following command to initialize and sync the database:")
        console.print("\n    [bold cyan]firm-lens init-db[/bold cyan]\n")
        sys.exit(1)
    
    if output is None:
        out_dir = os.path.join(os.path.expanduser('~'), 'Downloads', 'FirmLens_Reports', 'Static')
    else:
        # Check if user passed a directory ending in a slash, or an existing directory
        if output.endswith(('/', '\\')) or os.path.isdir(output):
            out_dir = output
        else:
            # Treat the last part as the file name, and the rest as the directory
            out_path = Path(output)
            out_dir = str(out_path.parent)
            base_name = out_path.name

    if not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)
        
    run_analyzers_pipeline(firmware_path, report_format, out_dir, base_name)


@cli.command(help="Initialize and synchronize the localized relational database cache with global threat feeds.")
def init_db():
    console.print("[info] Initializing localized vulnerability relational database schemas...[/info]")
    try:
        from firm_lens.data.init_intel import initialize_vulnerability_db
        initialize_vulnerability_db()
        console.print("[success]Local database storage architecture initialized safely.[/success]")
        
        console.print("[info] Connecting to public security ingestion boundaries for live synchronization...[/info]")
        from firm_lens.utils.bootstrap_intel import sync_global_threat_feeds
        records_updated = sync_global_threat_feeds()
        console.print(f"[success]Threat Intel Matrix updated. Cached {records_updated} live telemetry records safely inside data/vulnerabilities.db[/success]")
    except Exception as e:
        console.print(f"[error]Database Sync Initialization Aborted: {str(e)}[/error]")


# ============================================================
# MASTER DATA FLOW & CONTEXT ORCHESTRATION PIPELINE
# ============================================================
def run_analyzers_pipeline(path: str, report_format: str, out_dir: str, base_filename: str):
    try:
        with open(path, "rb") as f:
            raw_binary_bytes = f.read()
    except Exception as e:
        console.print(f"[error]File Processing Fault: Unable to load data stream: {str(e)}[/error]")
        return

    domain_map = {
        "FingerprintAnalyzer": "Platform Architecture & Component Catalog",
        "SecureBootAnalyzer": "Hardware-Rooted Boot Integrity Assessments",
        "FlashEncryptionAnalyzer": "Data-at-Rest Storage Cryptography Obfuscation",
        "SecretsAnalyzer": "Static Cryptographic Key & Credential Escrow Checks",
        "CryptoAnalyzer": "Cryptographic Primitive Configuration Profiles",
        "ESP32PartitionAnalyzer": "Logical Storage Layout & Boundary Integrity Audits",
        "DangerousFunctionAnalyzer": "Memory Safety & Execution Control-Flow Audits",
        "InsecureEndpointAnalyzer": "Infrastructure Interface & Network Surface Mapping",
        "BackdoorAnalyzer": "Unauthorized Access & Maintenance Interface Audits",
        "WeakXORAnalyzer": "Static Obfuscation & Data Masking Vulnerabilities",
        "CVEAnalyzer": "Software Composition Analysis & Supply Chain Intel"
    }

    raw_findings_pool = []
    dynamic_sdk_name = "Unverified Target Architecture"
    dynamic_sdk_version = "Unknown Baseline"

    # ============================================================
    # 1. BASELINE ENVIRONMENT FINGERPRINT INGESTION BOUNDARY
    # ============================================================
    try:
        env_prints = FingerprintAnalyzer().run(path)
        if env_prints:
            for f in env_prints:
                f.component = domain_map.get("FingerprintAnalyzer", "Platform Architecture & Component Catalog")
                if hasattr(f, 'evidence') and "v" in f.evidence:
                    dynamic_sdk_name = "ESP-IDF Environment Native"
                    dynamic_sdk_version = f.evidence.replace("Version tag:", "").strip()
            raw_findings_pool.extend(env_prints)
            
            cve_prints = CVEAnalyzer().run(env_prints)
            if cve_prints:
                for f in cve_prints:
                    f.component = domain_map.get("CVEAnalyzer", "Software Composition Analysis & Supply Chain Intel")
                raw_findings_pool.extend(cve_prints)
        else:
            raw_findings_pool.append(Finding(
                id="FL-FINGER-SDK",
                evidence="Forensics Warning: Application compilation symbols are fully stripped.",
                component=domain_map.get("FingerprintAnalyzer")
            ))
    except Exception:
        pass

    firmware_map = {
        "raw_path": path,
        "raw_binary": raw_binary_bytes,
        "segments": [],
        "partitions": [],
        "is_unified_flash": True if os.path.getsize(path) >= 0x400000 else False,
        "sdk_name": dynamic_sdk_name,       
        "sdk_version": dynamic_sdk_version   
    }

    try:
        extractor = ESP32Extractor()
        extracted_map = extractor.extract(path)
        if extracted_map:
            firmware_map.update(extracted_map)
    except Exception:
        pass

    # ============================================================
    # 2. ACTIVE HARDWARE & COMPONENT AUDIT LOOPS
    # ============================================================
    analyzers = [
        SecureBootAnalyzer(), FlashEncryptionAnalyzer(), SecretsAnalyzer(),
        CryptoAnalyzer(), ESP32PartitionAnalyzer(),
        DangerousFunctionAnalyzer(), InsecureEndpointAnalyzer(), BackdoorAnalyzer(), 
        WeakXORAnalyzer(), CVEAnalyzer()
    ]

    for analyzer in analyzers:
        name = analyzer.__class__.__name__
        try:
            results = analyzer.run_with_map(path, firmware_map) if hasattr(analyzer, "run_with_map") else analyzer.run(path)
            if results:
                for f in results:
                    f.component = domain_map.get(name, "General Security Audits")
                    raw_findings_pool.append(f)
        except Exception as e:
            import traceback
            console.print(f"[error]CRITICAL FAULT in {name}: {str(e)}[/error]")
            console.print(f"[dim red]{traceback.format_exc()}[/dim red]")


    # ============================================================
    # 3. STRICT ID-BASED ROLLUP DEDUPLICATION ENGINE
    # ============================================================
    deduped_registry = {}
    for f in raw_findings_pool:
        # Group strictly by ID to guarantee a single row per vulnerability type
        dedup_key = str(f.id).strip().upper()
        
        offset_str = str(f.offset).strip()
        clean_ev = str(f.evidence).replace("Primitive string instruction match: ", "").strip("'\" ")
        
        # Globally enforce 1:1 mapping by prepending offset if not already present
        if not clean_ev.startswith("[0x"):
            clean_ev = f"[{offset_str}] {clean_ev}"
            
        if dedup_key not in deduped_registry:
            deduped_registry[dedup_key] = f
            f.tracked_offsets = {offset_str}
            f.tracked_evidence = {clean_ev}
        else:
            target_f = deduped_registry[dedup_key]
            target_f.tracked_offsets.add(offset_str)
            target_f.tracked_evidence.add(clean_ev)

    aggregated_pool = []
    for f in deduped_registry.values():
        # 1. Format the offsets
        if hasattr(f, 'tracked_offsets') and len(f.tracked_offsets) > 1:
            offsets_list = sorted(list(f.tracked_offsets))
            if len(offsets_list) > 3:
                f.offset = f"{offsets_list[0]} ... {offsets_list[-1]} ({len(offsets_list)} Locations)"
            else:
                f.offset = ", ".join(offsets_list)
        
        # 2. Filter out obviously noisy evidence before packing
        meaningful_evidence = []
        for ev in getattr(f, 'tracked_evidence', []):
            # Extract just the string part after the [0x...] tag for noise checking
            ev_content = re.sub(r'^\[0x[0-9a-fA-F]+\]\s*', '', ev)
            
            if re.search(r'%[sdpuxn08]', ev_content): continue
            if re.match(r'^[0-9a-fA-F\s]+$', ev_content): continue
            if len(ev_content.strip()) < 3: continue
            meaningful_evidence.append(ev)

        # 3. Package the final evidence AS A PURE NATIVE ARRAY
        evidence_list = sorted(list(set(meaningful_evidence)))
        
        if evidence_list:
            # Strictly build a new native list. No str() conversions!
            f.evidence = [e for e in evidence_list]
        else:
            offsets_list = sorted(list(getattr(f, 'tracked_offsets', [])))
            f.evidence = [f"Memory layout allocation at offset: {o}" for o in offsets_list]
            
        # 4. Save to the final pool
        aggregated_pool.append(f)

    # ============================================================
    # 4. DATA-LAYER ORCHESTRATION VIA RELATIONAL KNOWLEDGE MATRICES
    # ============================================================
    base_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(base_dir, "data", "vulnerabilities.db")
    
    static_rules = load_centralized_analyzer_rules()
    remediations_cache = {}
    compliance_cache = {}
    cve_threat_telemetry = {}

    if os.path.exists(db_path):
        try:
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                
                # Extract engineers blueprints
                cursor.execute("SELECT cwe_id, blueprint_text FROM remediations")
                remediations_cache = {row[0].strip().upper(): row[1] for row in cursor.fetchall()}
                
                # Extract dynamic regulatory mappings
                cursor.execute("SELECT cwe_id, nist_sp_800_213, etsi_en_303_645 FROM compliance_mappings")
                for cwe, nist, etsi in cursor.fetchall():
                    compliance_cache[cwe.strip().upper()] = {"nist": nist, "etsi": etsi}
                
                # Track real-world live telemetry precisely by individual CVE ID
                cursor.execute("SELECT cve_id, epss_score, kev_status FROM threat_intel_cache")
                for cve, epss, kev in cursor.fetchall():
                    cve_threat_telemetry[cve.strip().upper()] = {"epss": epss, "kev": kev}
        except Exception as e:
            console.print(f"[warning] Relational intelligence compilation bypassed: {str(e)}[/warning]")

    # ============================================================
    # 5. POST-PROCESSING ENRICHMENT & COMPLIANCE BUCKETING
    # ============================================================
    scoreboard = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    all_findings = {}

    for f in aggregated_pool:
        f_id_upper = str(f.id).strip().upper()
        
        # Populate static layout configurations
        if f_id_upper in static_rules:
            meta = static_rules[f_id_upper]
            f.title = meta.get("title", f.title)
            f.description = meta.get("description", f.description)
            
            raw_cwes = getattr(f, "cwes", [])
            if isinstance(raw_cwes, str): 
                raw_cwes = [raw_cwes]
            cleaned_cwes = [str(c).strip() for c in raw_cwes if str(c).strip() and str(c).strip() != "-"]
            
            if not cleaned_cwes:
                f.cwes = meta.get("cwes", [])
            else:
                f.cwes = cleaned_cwes
                
            f.severity = meta.get("base_severity", "Medium").capitalize()

        # Handle relational mappings tied strictly to the CWE weakness type
        for cwe in f.cwes:
            cwe_key = str(cwe).strip().upper()
            
            # Inject remediation blueprint text with DYNAMIC CONTEXT
            if cwe_key in remediations_cache:
                base_remediation = remediations_cache[cwe_key]
                dynamic_context = ""
                
                # --- DYNAMIC INJECTION LOGIC ---
                # Safely extract the first piece of evidence for context parsing if it exists
                first_evidence = str(f.evidence[0]) if isinstance(f.evidence, list) and len(f.evidence) > 0 else str(f.evidence)
                
                if f_id_upper == "FIRM-ESP32-PART-030" and "Target Partition" in first_evidence:
                    match = re.search(r"Target Partition '([^']+)'", first_evidence)
                    if match:
                        dynamic_context = f" Specifically, ensure the '{match.group(1)}' partition located at {f.offset} is encrypted."
                
                elif f_id_upper == "FL-NETW-IP":
                    base_remediation = "Migrate static hardcoded IPv4 network boundaries to dynamic DHCP provisioning or encrypted configuration storage blocks."
                    dynamic_context = f" Specifically, target the static IP addresses identified at offset(s): {f.offset}."
                    
                elif f_id_upper == "FL-BACKDOOR-PATH" and "endpoint reference" in first_evidence:
                    endpoint_path = first_evidence.split(': ')[-1].strip()
                    dynamic_context = f" Ensure the endpoint '{endpoint_path}' is securely authenticated or stripped before production."
                
                elif f_id_upper == "FL-CRED-STRUCT":
                    dynamic_context = f" The exposed structures are located at offset(s): {f.offset}."

                # Append the dynamic context to the base enterprise text
                f.remediation_blueprint = f"{base_remediation}{dynamic_context}"
                
            # Dynamically load the regulatory framework mappings from DB
            if cwe_key in compliance_cache:
                comp = compliance_cache[cwe_key]

        # Isolate direct CVE identifiers to enrich with real-world threat metrics
        potential_cve = None
        if f_id_upper.startswith("CVE-"):
            potential_cve = f_id_upper
        elif hasattr(f, 'cve_id') and f.cve_id:
            potential_cve = str(f.cve_id).strip().upper()

        if potential_cve and potential_cve in cve_threat_telemetry:
            intel = cve_threat_telemetry[potential_cve]
            f.threat_intelligence_telemetry["epss_weaponization_probability"] = f"{intel['epss'] * 100:.2f}% (Live Threat Feed)"
            if intel["kev"] == 1 and f.severity in ["High", "Medium"]:
                f.severity = "Critical"

        # Record changes into the active runtime scoreboard metrics
        scoreboard[f.severity] = scoreboard.get(f.severity, 0) + 1
        
        # Structure the payload into proper domain components for the ReportGenerator
        module_bucket = "General"
        for k, v in domain_map.items():
            if v == f.component:
                module_bucket = k
                break
                
        if module_bucket not in all_findings:
            all_findings[module_bucket] = []
        all_findings[module_bucket].append(f)

    # ============================================================
    # SCOREBOARD METRIC RENDERER
    # ============================================================
    console.print("\n" + "=" * 62, style="titlelines")
    console.print("FIRMLENS PIPELINE SCAN SECURITY MATRIX COMPLETE", style="title")
    console.print("=" * 62, style="titlelines")
    
    table_board = Table(show_header=False, box=None, padding=(0, 2), expand=True)
    table_board.add_column("Category", style="bold")
    table_board.add_column("Count", justify="right")

    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        count = scoreboard.get(sev, 0)
        color = "red" if sev == "Critical" else "orange3" if sev == "High" else "yellow" if sev == "Medium" else "green" if sev == "Low" else "cyan"
        table_board.add_row(f"[bold {color}]{sev.upper()}[/bold {color}]", f"[bold {color}]{count}[/bold {color}]")
        
    console.print(Panel(table_board, box=rich.box.SQUARE, border_style="gray50", width=50))

    # Clean display name and prevent duplicate printing
    target_asset_name = os.path.basename(path)
    generator = ReportGenerator(out_dir)
    generator.generate(all_findings, report_format, out_dir, filename=base_filename, asset_name=target_asset_name)