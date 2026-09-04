#!/usr/bin/env python3
import json
import csv
from pathlib import Path
from typing import Dict, Set, List

from firm_lens.extractor.esp32_extractor import ESP32Extractor
from firm_lens.analyzers.esp32_partition_analyzer import ESP32PartitionAnalyzer
from firm_lens.analyzers.secrets_analyzer import SecretsAnalyzer
from firm_lens.analyzers.crypto_analyzer import CryptoAnalyzer
from firm_lens.analyzers.flash_encryption_analyzer import FlashEncryptionAnalyzer
from firm_lens.analyzers.secure_boot_analyzer import SecureBootAnalyzer
from firm_lens.analyzers.backdoor_analyzer import BackdoorAnalyzer
from firm_lens.analyzers.dangerous_function_analyzer import DangerousFunctionAnalyzer
from firm_lens.analyzers.fingerprint_analyzer import FingerprintAnalyzer
from firm_lens.utils.rules_loader import load_centralized_analyzer_rules

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "replication" / "test_samples"
RESULTS_DIR = Path(__file__).resolve().parent.parent / "replication" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# Ground truth CWE definitions by firmware classification profile
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

def evaluate_all():
    rules = load_centralized_analyzer_rules()
    extractor = ESP32Extractor()
    analyzers = [
        ESP32PartitionAnalyzer(),
        SecretsAnalyzer(),
        CryptoAnalyzer(),
        FlashEncryptionAnalyzer(),
        SecureBootAnalyzer(),
        BackdoorAnalyzer(),
        DangerousFunctionAnalyzer(),
        FingerprintAnalyzer(),
    ]

    target_results = {}
    total_tp = 0
    total_fp = 0
    total_fn = 0

    all_possible_cwes = sorted(list(FLASH_DUMP_CWES | APP_BINARY_CWES))
    cwe_detection_stats = {cwe: {"expected": 0, "detected": 0} for cwe in all_possible_cwes}

    print(f" Commencing Multi-Target Empirical Accuracy Evaluation (N={len(GROUND_TRUTH)} Targets)...")

    for sample_name, expected_cwes in sorted(GROUND_TRUTH.items()):
        sample_path = SAMPLES_DIR / sample_name
        if not sample_path.exists():
            continue

        fmap = extractor.extract(str(sample_path))
        if not fmap.get("partitions") and fmap.get("raw_binary"):
            fmap["partitions"] = analyzers[0]._deep_carve_flash_space(fmap["raw_binary"])

        findings = []
        for analyzer in analyzers:
            if hasattr(analyzer, "run_with_map"):
                res = analyzer.run_with_map(str(sample_path), fmap)
                if res:
                    findings.extend(res)

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

        precision = (tp / (tp + fp) * 100) if (tp + fp) > 0 else 0.0
        recall = (tp / (tp + fn) * 100) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        for cwe in expected_cwes:
            cwe_detection_stats[cwe]["expected"] += 1
            if cwe in detected_cwes:
                cwe_detection_stats[cwe]["detected"] += 1

        target_results[sample_name] = {
            "expected_cwes": sorted(list(expected_cwes)),
            "detected_cwes": sorted(list(detected_cwes)),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": round(precision, 2),
            "recall": round(recall, 2),
            "f1_score": round(f1, 2)
        }

        print(f"  {sample_name:<30} | P: {precision:6.2f}% | R: {recall:6.2f}% | F1: {f1:6.2f}% (TP={tp}, FP={fp}, FN={fn})")

    # Aggregate Micro Metrics
    micro_precision = (total_tp / (total_tp + total_fp) * 100) if (total_tp + total_fp) > 0 else 0.0
    micro_recall = (total_tp / (total_tp + total_fn) * 100) if (total_tp + total_fn) > 0 else 0.0
    micro_f1 = (2 * micro_precision * micro_recall / (micro_precision + micro_recall)) if (micro_precision + micro_recall) > 0 else 0.0

    # Aggregate Macro Metrics
    macro_precision = sum(r["precision"] for r in target_results.values()) / len(target_results)
    macro_recall = sum(r["recall"] for r in target_results.values()) / len(target_results)
    macro_f1 = sum(r["f1_score"] for r in target_results.values()) / len(target_results)

    final_payload = {
        "summary": {
            "total_targets": len(target_results),
            "micro_precision": round(micro_precision, 2),
            "micro_recall": round(micro_recall, 2),
            "micro_f1": round(micro_f1, 2),
            "macro_precision": round(macro_precision, 2),
            "macro_recall": round(macro_recall, 2),
            "macro_f1": round(macro_f1, 2),
        },
        "target_breakdown": target_results,
        "cwe_recall_breakdown": {
            k: {
                "expected": v["expected"],
                "detected": v["detected"],
                "recall": round((v["detected"] / v["expected"] * 100), 2) if v["expected"] > 0 else 0.0
            }
            for k, v in cwe_detection_stats.items()
        }
    }

    # Save JSON report
    json_path = RESULTS_DIR / "multi_target_accuracy.json"
    with open(json_path, "w") as f:
        json.dump(final_payload, f, indent=2)

    # Save Per-CWE CSV
    csv_path = RESULTS_DIR / "per_cwe_metrics.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["cwe_id", "expected_count", "detected_count", "recall_pct"])
        writer.writeheader()
        for cwe_id, stats in final_payload["cwe_recall_breakdown"].items():
            writer.writerow({
                "cwe_id": cwe_id,
                "expected_count": stats["expected"],
                "detected_count": stats["detected"],
                "recall_pct": stats["recall"]
            })

    print("\n=======================================================")
    print(" Multi-Target Empirical Accuracy Summary")
    print("=======================================================")
    print(f" Micro Precision : {micro_precision:.2f}%")
    print(f" Micro Recall    : {micro_recall:.2f}%")
    print(f" Micro F1-Score  : {micro_f1:.2f}%")
    print(f" Macro Precision : {macro_precision:.2f}%")
    print(f" Macro Recall    : {macro_recall:.2f}%")
    print(f" Macro F1-Score  : {macro_f1:.2f}%")
    print("=======================================================")
    print(f" Artifacts successfully written:\n  {json_path}\n  {csv_path}")

if __name__ == "__main__":
    evaluate_all()