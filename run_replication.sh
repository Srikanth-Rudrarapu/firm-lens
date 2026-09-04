#!/usr/bin/env bash
set -e

echo "============================================================"
echo " FirmLens Automated Research Replication Suite"
echo "============================================================"

# Ensure the virtual environment is active so dependencies are found
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

# 1. Unit & Parser Test Suites
echo -e "\n 1/8 Running Unit & Parser Test Suites..."
pytest -v tests/

# 2. Static Benchmark Performance & Throughput
echo -e "\n 2/8 Running Comprehensive Performance Profiling (N=11)..."
python3 experiments/benchmark_performance.py

# 3. Multi-Target Ground Truth Accuracy Evaluation
echo -e "\n 3/8: Executing Multi-Target Accuracy Evaluation (11 Binaries)..."
python3 experiments/evaluate_accuracy.py

# 4. Tool Capability Comparison Matrix
echo -e "\n 4/8: Compiling Tool Capability & Performance Comparison..."
python3 experiments/evaluate_tool_comparison.py

# 5. Ablation Study
echo -e "\n 5/8 Running Ablation Study..."
python3 experiments/run_ablation_study.py


# 6. Dynamic HIL Hardware Benchmarks (if ESP32 is attached)
if ls /dev/cu.usbserial* 1> /dev/null 2>&1; then
    SERIAL_PORT=$(ls /dev/cu.usbserial* | head -n 1)
    echo -e "\n 6/8 Physical ESP32 detected on ${SERIAL_PORT}. Running HIL benchmarks..."
    python3 experiments/benchmark_hil.py "$SERIAL_PORT"
else
    echo -e "\n 6/8 Skipping live HIL hardware benchmarks (No physical ESP32 detected)."
fi

# 7. Aggregate Statistical Metrics Generation
echo -e "\n 7/8: Computing 95% Confidence Intervals & Aggregate Statistics..."
python3 -c "
import json, csv, math, statistics
from pathlib import Path

csv_path = Path('replication/results/performance_benchmark.csv')
with open(csv_path, 'r') as f:
    rows = list(csv.DictReader(f))

latencies = [float(r['mean_latency_sec']) for r in rows]
throughputs = [float(r['throughput_mb_s']) for r in rows]
mems = [float(r['peak_memory_mb']) for r in rows]

def get_stats(data):
    n = len(data)
    mean = statistics.mean(data)
    std = statistics.stdev(data) if n > 1 else 0.0
    median = statistics.median(data)
    ci95 = 1.96 * (std / math.sqrt(n)) if n > 1 else 0.0
    return {
        'n': n,
        'mean': round(mean, 4),
        'std_dev': round(std, 4),
        'median': round(median, 4),
        'min': round(min(data), 4),
        'max': round(max(data), 4),
        'ci_95': round(ci95, 4)
    }

stats_summary = {
    'latency_seconds': get_stats(latencies),
    'throughput_mb_s': get_stats(throughputs),
    'peak_memory_mb': get_stats(mems)
}

out_path = Path('replication/results/aggregate_statistical_metrics.json')
with open(out_path, 'w') as f:
    json.dump(stats_summary, f, indent=2)

print(' Aggregated metrics successfully refreshed.')
"

# 8. Generate Final IEEE Figures
echo -e "\n 8/8 Generating final IEEE visualization plots..."
python3 experiments/generate_figures.py

echo -e "\n============================================================"
echo " Replication Pipeline Completed Successfully."
echo " Results, metrics, and figures saved to replication/results/"
echo "============================================================"