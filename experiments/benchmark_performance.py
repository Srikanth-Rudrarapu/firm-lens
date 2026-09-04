#!/usr/bin/env python3

import csv
import json
import os
import platform
import statistics
import subprocess
import time
import tracemalloc
from pathlib import Path

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


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

SAMPLES_DIR = PROJECT_ROOT / "replication" / "test_samples"
RESULTS_DIR = PROJECT_ROOT / "replication" / "results"

RESULTS_DIR.mkdir(parents=True, exist_ok=True)

CSV_OUT = RESULTS_DIR / "performance_benchmark.csv"
TRIAL_CSV_OUT = RESULTS_DIR / "performance_trial_data.csv"
META_OUT = RESULTS_DIR / "environment_metadata.json"


# ---------------------------------------------------------------------------
# Environment metadata
# ---------------------------------------------------------------------------

def collect_environment_metadata():
    """
    Collect reproducibility metadata for the benchmark environment.

    The metadata is intentionally captured at benchmark execution time so
    the resulting artifact records the exact runtime environment used for
    the experiment.
    """

    total_ram_gb = 0.0

    try:
        if platform.system() == "Darwin":
            mem_str = subprocess.check_output(
                ["sysctl", "-n", "hw.memsize"]
            ).decode().strip()

            total_ram_gb = round(
                int(mem_str) / (1024 ** 3),
                2
            )

        elif platform.system() == "Linux":
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        total_ram_gb = round(
                            int(line.split()[1]) / (1024 ** 2),
                            2
                        )
                        break

    except Exception:
        total_ram_gb = 0.0

    return {
        "os_name": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "total_ram_gb": total_ram_gb,
        "python_version": platform.python_version(),
        "timestamp_utc": time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.gmtime()
        )
    }


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------

def run_performance_benchmark(trials: int = 10):

    # -----------------------------------------------------------------------
    # Validate benchmark configuration
    # -----------------------------------------------------------------------

    if trials < 1:
        raise ValueError("trials must be >= 1")

    # -----------------------------------------------------------------------
    # Capture environment metadata
    # -----------------------------------------------------------------------

    env_meta = collect_environment_metadata()

    with open(META_OUT, "w") as f:
        json.dump(
            env_meta,
            f,
            indent=2
        )

    # -----------------------------------------------------------------------
    # Discover firmware samples
    # -----------------------------------------------------------------------

    sample_files = sorted(
        SAMPLES_DIR.glob("*.bin")
    )

    if not sample_files:
        print(
            f"[!] No samples found in {SAMPLES_DIR}"
        )
        return

    # -----------------------------------------------------------------------
    # Initialize FirmLens components
    # -----------------------------------------------------------------------

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
        InsecureEndpointAnalyzer(),
        WeakXORAnalyzer(),
    ]

    # -----------------------------------------------------------------------
    # Result containers
    # -----------------------------------------------------------------------

    summary_records = []
    trial_records = []

    print(
        f" Running Comprehensive Performance & Memory Profiling "
        f"(N={len(sample_files)}, Trials={trials})..."
    )

    # -----------------------------------------------------------------------
    # Benchmark each firmware target
    # -----------------------------------------------------------------------

    for sample in sample_files:

        size_bytes = os.path.getsize(sample)

        size_mb = round(
            size_bytes / (1024 * 1024),
            2
        )

        durations = []
        peak_mem_mb = []

        findings = []

        # ---------------------------------------------------------------
        # Execute repeated trials
        # ---------------------------------------------------------------

        for trial_number in range(1, trials + 1):

            tracemalloc.start()

            t0 = time.perf_counter()

            # -----------------------------------------------------------
            # Firmware extraction
            # -----------------------------------------------------------

            fmap = extractor.extract(
                str(sample)
            )

            # -----------------------------------------------------------
            # Deep partition carving fallback
            # -----------------------------------------------------------

            if (
                not fmap.get("partitions")
                and fmap.get("raw_binary")
            ):
                fmap["partitions"] = (
                    analyzers[0]._deep_carve_flash_space(
                        fmap["raw_binary"]
                    )
                )

            # -----------------------------------------------------------
            # Run analyzers
            # -----------------------------------------------------------

            trial_findings = []

            for analyzer in analyzers:

                if hasattr(
                    analyzer,
                    "run_with_map"
                ):

                    res = analyzer.run_with_map(
                        str(sample),
                        fmap
                    )

                    if res:
                        trial_findings.extend(res)

            t1 = time.perf_counter()

            # -----------------------------------------------------------
            # Memory measurement
            # -----------------------------------------------------------

            _, peak = tracemalloc.get_traced_memory()

            tracemalloc.stop()

            # -----------------------------------------------------------
            # Record raw trial measurements
            # -----------------------------------------------------------

            latency_sec = t1 - t0

            peak_memory_mb = (
                peak / (1024 * 1024)
            )

            durations.append(
                latency_sec
            )

            peak_mem_mb.append(
                peak_memory_mb
            )

            
            findings = trial_findings

            trial_records.append({
                "target": sample.name,
                "trial": trial_number,
                "size_mb": size_mb,
                "latency_sec": round(
                    latency_sec,
                    6
                ),
                "peak_memory_mb": round(
                    peak_memory_mb,
                    6
                )
            })

        # ---------------------------------------------------------------
        # Per-target statistics
        # ---------------------------------------------------------------

        mean_time = statistics.mean(
            durations
        )

        std_time = (
            statistics.stdev(durations)
            if len(durations) > 1
            else 0.0
        )

        mean_peak_mem = statistics.mean(
            peak_mem_mb
        )

        throughput = (
            size_mb / mean_time
            if mean_time > 0
            else 0.0
        )

        # ---------------------------------------------------------------
        # Existing summary artifact
        # ---------------------------------------------------------------

        record = {
            "target": sample.name,
            "size_mb": size_mb,
            "mean_latency_sec": round(
                mean_time,
                4
            ),
            "std_latency_sec": round(
                std_time,
                4
            ),
            "throughput_mb_s": round(
                throughput,
                2
            ),
            "peak_memory_mb": round(
                mean_peak_mem,
                3
            ),
            "findings_count": len(findings)
        }

        summary_records.append(
            record
        )

        print(
            f" {sample.name:<30} | "
            f"{size_mb:5.2f} MB | "
            f"{mean_time:.4f}s ± {std_time:.4f}s | "
            f"{throughput:6.2f} MB/s | "
            f"Peak RAM: {mean_peak_mem:.2f} MB"
        )

    # -----------------------------------------------------------------------
    # Write per-target summary CSV
    # -----------------------------------------------------------------------

    with open(
        CSV_OUT,
        "w",
        newline=""
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=[
                "target",
                "size_mb",
                "mean_latency_sec",
                "std_latency_sec",
                "throughput_mb_s",
                "peak_memory_mb",
                "findings_count"
            ]
        )

        writer.writeheader()
        writer.writerows(
            summary_records
        )

    # -----------------------------------------------------------------------
    # Write raw trial-level CSV
    # -----------------------------------------------------------------------

    with open(
        TRIAL_CSV_OUT,
        "w",
        newline=""
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=[
                "target",
                "trial",
                "size_mb",
                "latency_sec",
                "peak_memory_mb"
            ]
        )

        writer.writeheader()
        writer.writerows(
            trial_records
        )

    # -----------------------------------------------------------------------
    # Calculate overall statistics directly from raw trial observations
    #
    # IMPORTANT:
    # These statistics are based on the individual trial measurements,
    # not the per-target means.
    # -----------------------------------------------------------------------

    latency_trials = [
        float(row["latency_sec"])
        for row in trial_records
    ]

    memory_trials = [
        float(row["peak_memory_mb"])
        for row in trial_records
    ]

    # Throughput is derived from each raw trial's latency and target size.
    throughput_trials = [
        (
            float(row["size_mb"])
            / float(row["latency_sec"])
        )
        for row in trial_records
        if float(row["latency_sec"]) > 0
    ]

    def calculate_statistics(data):

        n = len(data)

        if n == 0:
            return {
                "n": 0,
                "mean": 0.0,
                "std_dev": 0.0,
                "median": 0.0,
                "min": 0.0,
                "max": 0.0,
                "ci_95": 0.0
            }

        mean = statistics.mean(data)

        std_dev = (
            statistics.stdev(data)
            if n > 1
            else 0.0
        )

        median = statistics.median(data)

        ci95 = (
            1.96 * (std_dev / (n ** 0.5))
            if n > 1
            else 0.0
        )

        return {
            "n": n,
            "mean": round(mean, 6),
            "std_dev": round(std_dev, 6),
            "median": round(median, 6),
            "min": round(min(data), 6),
            "max": round(max(data), 6),
            "ci_95": round(ci95, 6)
        }

    aggregate_statistics = {
        "method": (
            "Statistics computed from individual benchmark "
            "trial observations"
        ),
        "targets": len(sample_files),
        "trials_per_target": trials,
        "total_trial_observations": len(trial_records),
        "confidence_interval": (
            "95% normal-approximation CI using 1.96 * SE"
        ),
        "latency_seconds": calculate_statistics(
            latency_trials
        ),
        "throughput_mb_s": calculate_statistics(
            throughput_trials
        ),
        "peak_memory_mb": calculate_statistics(
            memory_trials
        )
    }

    aggregate_json = (
        RESULTS_DIR /
        "performance_aggregate_statistics.json"
    )

    with open(
        aggregate_json,
        "w"
    ) as f:

        json.dump(
            aggregate_statistics,
            f,
            indent=2
        )

    # -----------------------------------------------------------------------
    # Final output
    # -----------------------------------------------------------------------

    print("\n Performance artifacts saved:")

    print(
        f"  {META_OUT}"
    )

    print(
        f"  {CSV_OUT}"
    )

    print(
        f"  {TRIAL_CSV_OUT}"
    )

    print(
        f"  {aggregate_json}"
    )

    print("\n Raw trial observations:")
    print(
        f"  {len(trial_records)} "
        f"measurements "
        f"({len(sample_files)} targets × {trials} trials)"
    )

    print("\n Aggregate latency statistics:")
    print(
        f"  Mean   : "
        f"{aggregate_statistics['latency_seconds']['mean']:.6f}s"
    )

    print(
        f"  SD     : "
        f"{aggregate_statistics['latency_seconds']['std_dev']:.6f}s"
    )

    print(
        f"  Median : "
        f"{aggregate_statistics['latency_seconds']['median']:.6f}s"
    )

    print(
        f"  95% CI : "
        f"±{aggregate_statistics['latency_seconds']['ci_95']:.6f}s"
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    run_performance_benchmark()