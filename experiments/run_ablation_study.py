#!/usr/bin/env python3
import csv
import json
import time
from pathlib import Path
from typing import Dict, List, Set, Type

from firm_lens.extractor.esp32_extractor import ESP32Extractor
from firm_lens.analyzers.esp32_partition_analyzer import ESP32PartitionAnalyzer
from firm_lens.analyzers.secrets_analyzer import SecretsAnalyzer
from firm_lens.analyzers.crypto_analyzer import CryptoAnalyzer
from firm_lens.analyzers.flash_encryption_analyzer import FlashEncryptionAnalyzer
from firm_lens.analyzers.secure_boot_analyzer import SecureBootAnalyzer
from firm_lens.analyzers.backdoor_analyzer import BackdoorAnalyzer
from firm_lens.analyzers.dangerous_function_analyzer import DangerousFunctionAnalyzer
from firm_lens.analyzers.fingerprint_analyzer import FingerprintAnalyzer
from firm_lens.analyzers.insecure_endpoint_analyzer import InsecureEndpointAnalyzer
from firm_lens.analyzers.weak_xor_analyzer import WeakXORAnalyzer
from firm_lens.utils.rules_loader import load_centralized_analyzer_rules

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "replication" / "test_samples"
RESULTS_DIR = Path(__file__).resolve().parent.parent / "replication" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

FLASH_DUMP_CWES = {
    "CWE-120", "CWE-1310", "CWE-1329", "CWE-134", 
    "CWE-312", "CWE-327", "CWE-328", "CWE-347", "CWE-425", "CWE-912"
}

APP_BINARY_CWES = {
    "CWE-120", "CWE-134", "CWE-312", 
    "CWE-327", "CWE-328", "CWE-347", "CWE-425", "CWE-912"
}

GROUND_TRUTH: Dict[str, Set[str]] = {
    "damn_vuln.bin": FLASH_DUMP_CWES,
    "flash_dump.bin": FLASH_DUMP_CWES,
    "forensic_target_image.bin": FLASH_DUMP_CWES,
    "full_flash.bin": FLASH_DUMP_CWES,
    "hardware_extracted_flash.bin": FLASH_DUMP_CWES,
    "tasmota32-bluetooth.bin": APP_BINARY_CWES,
    "tasmota32-display.bin": APP_BINARY_CWES,
    "tasmota32-ir.bin": APP_BINARY_CWES,
    "tasmota32-webcam.bin": APP_BINARY_CWES,
    "tasmota32c2.bin": APP_BINARY_CWES,
    "wifi.bin": APP_BINARY_CWES,
}

ALL_ANALYZERS = [
    ESP32PartitionAnalyzer,
    SecretsAnalyzer,
    CryptoAnalyzer,
    FlashEncryptionAnalyzer,
    SecureBootAnalyzer,
    BackdoorAnalyzer,
    DangerousFunctionAnalyzer,
    FingerprintAnalyzer,
    InsecureEndpointAnalyzer,
    WeakXORAnalyzer,
]

def run_configuration(excluded_cls: Type = None):
    rules = load_centralized_analyzer_rules()
    extractor = ESP32Extractor()
    active_analyzers = [cls() for cls in ALL_ANALYZERS if cls != excluded_cls]
    
    total_tp = 0
    total_fp = 0
    total_fn = 0
    total_findings = 0
    
    t0 = time.perf_counter()
    
    for sample_name, expected_cwes in sorted(GROUND_TRUTH.items()):
        sample_path = SAMPLES_DIR / sample_name
        if not sample_path.exists():
            continue
            
        fmap = extractor.extract(str(sample_path))
        # Deep carve partitions if partition table analyzer is active
        if any(isinstance(a, ESP32PartitionAnalyzer) for a in active_analyzers):
            part_analyzer = next(a for a in active_analyzers if isinstance(a, ESP32PartitionAnalyzer))
            if not fmap.get("partitions") and fmap.get("raw_binary"):
                fmap["partitions"] = part_analyzer._deep_carve_flash_space(fmap["raw_binary"])
                
        findings = []
        for analyzer in active_analyzers:
            if hasattr(analyzer, "run_with_map"):
                res = analyzer.run_with_map(str(sample_path), fmap)
                if res:
                    findings.extend(res)
                    
        total_findings += len(findings)
        
        detected_cwes = set()
        for f in findings:
            rule_meta = rules.get(f.id.strip().upper(), {})
            for c in rule_meta.get("cwes", []):
                detected_cwes.add(c)
                
        tp = len(expected_cwes & detected_cwes)
        fp = len(detected_cwes - expected_cwes)
        fn = len(expected_cwes - detected_cwes)
        
        total_tp += tp
        total_fp += fp
        total_fn += fn
        
    duration = time.perf_counter() - t0
    
    precision = (total_tp / (total_tp + total_fp) * 100) if (total_tp + total_fp) > 0 else 0.0
    recall = (total_tp / (total_tp + total_fn) * 100) if (total_tp + total_fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    
    return {
        "precision": round(precision, 2),
        "recall": round(recall, 2),
        "f1_score": round(f1, 2),
        "total_findings": total_findings,
        "execution_time_sec": round(duration, 4)
    }

def main():
    print(" Starting Analyzer Ablation Study (Evaluating Marginal Contribution across 11 targets)...")
    
    # 1. Baseline: All Analyzers Active
    baseline_stats = run_configuration(excluded_cls=None)
    print(f"\n[Baseline - Full Pipeline] Recall: {baseline_stats['recall']:.2f}% | Findings: {baseline_stats['total_findings']} | Time: {baseline_stats['execution_time_sec']:.4f}s")
    
    ablation_records = []
    ablation_records.append({
        "configuration": "Full Pipeline (Baseline)",
        "excluded_module": "None",
        "recall_pct": baseline_stats["recall"],
        "precision_pct": baseline_stats["precision"],
        "f1_score": baseline_stats["f1_score"],
        "total_findings": baseline_stats["total_findings"],
        "delta_recall_pct": 0.0,
        "delta_findings": 0,
        "execution_time_sec": baseline_stats["execution_time_sec"]
    })
    
    # 2. Leave-One-Out for each analyzer
    for analyzer_cls in ALL_ANALYZERS:
        name = analyzer_cls.__name__
        stats = run_configuration(excluded_cls=analyzer_cls)
        
        delta_recall = round(stats["recall"] - baseline_stats["recall"], 2)
        delta_findings = stats["total_findings"] - baseline_stats["total_findings"]
        
        print(f"  Ablated: {name:<28} | Recall: {stats['recall']:6.2f}% (Δ {delta_recall:+5.2f}%) | Findings: {stats['total_findings']:3d} (Δ {delta_findings:+4d})")
        
        ablation_records.append({
            "configuration": f"Without {name}",
            "excluded_module": name,
            "recall_pct": stats["recall"],
            "precision_pct": stats["precision"],
            "f1_score": stats["f1_score"],
            "total_findings": stats["total_findings"],
            "delta_recall_pct": delta_recall,
            "delta_findings": delta_findings,
            "execution_time_sec": stats["execution_time_sec"]
        })
        
    # Write CSV
    csv_out = RESULTS_DIR / "ablation_study.csv"
    with open(csv_out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "configuration", "excluded_module", "recall_pct", "precision_pct", 
            "f1_score", "total_findings", "delta_recall_pct", "delta_findings", "execution_time_sec"
        ])
        writer.writeheader()
        writer.writerows(ablation_records)
        
    # Write JSON
    json_out = RESULTS_DIR / "ablation_study.json"
    with open(json_out, "w") as f:
        json.dump(ablation_records, f, indent=2)
        
    print(f"\n Ablation study results saved:\n  {csv_out}\n  {json_out}")

if __name__ == "__main__":
    main()