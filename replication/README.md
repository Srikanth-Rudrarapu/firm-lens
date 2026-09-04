# FirmLens: Replication Package & Evaluation Benchmark

This repository contains the replication package, experiment harnesses, evaluation firmware targets, and analysis scripts for the research manuscript:

> **"FirmLens: Automated Static, Hardware-Rooted, and Dynamic HIL Vulnerability Analysis for Bare-Metal ESP32 Firmware"**

The evaluation suite reproduces all empirical metrics, modular ablation studies, and execution benchmarks reported in the manuscript across N=11 firmware targets.

---

## 1. Directory Structure

```text
.
├── experiments/
│   ├── benchmark_hil.py              # Dynamic UART hardware-in-the-loop triage runner
│   ├── benchmark_performance.py      # Latency, throughput, and memory profiling suite
│   ├── evaluate_accuracy.py          # Full empirical accuracy evaluation across N=11 targets
│   ├── evaluate_tool_comparison.py   # Baseline capability matrix generator
│   ├── generate_dataset_manifest.py  # SHA-256 binary validation generator
│   ├── generate_figures.py           # IEEE LaTeX figure compilation
│   └── run_ablation_study.py         # Modular leave-one-out analyzer ablation harness
├── firm_lens/                        # Core framework package
│   ├── analyzers/                    # Static partition, cryptographic, and memory analyzers
│   ├── dynamic/                      # UART HIL crash triage and frame monitors
│   └── extractor/                    # ESP32 binary extraction and partition table engine
├── replication/
│   ├── ground_truth/                 # Ground-truth taxonomy and manifest specifications
│   ├── results/                      # Canonical CSV/JSON evaluation data and generated figures
│   ├── test_samples/                 # Evaluation firmware targets (N=11)
│   └── run_replication.sh            # Automated artifact execution pipeline
└── paper/                            # Manuscript LaTeX source and bibliography
```

---

## 2. Environment Setup

### System Prerequisites
* **Operating System:** macOS (Darwin arm64) or Linux (x86_64 / aarch64)
* **Python Interpreter:** Python 3.12+ (Benchmarked on CPython 3.14.6)
* **Hardware Requirements:**
  * **Static Benchmarks (Steps 1–3):** No physical hardware required. Evaluates directly on pre-compiled binary images in `replication/test_samples/`.
  * **Dynamic HIL Triage (Step 4):** Requires an ESP32 / ESP32-S3 development board connected via USB-UART serial interface (e.g., `/dev/cu.usbserial-0001` on macOS or `/dev/ttyUSB0` on Linux at 115200 baud).

### Installation Options

**Option A: Install via PyPI (Stable Package)**
```bash
pip install firm-lens
```

**Option B: Install from Source (Replication Environment)**
```bash
git clone https://github.com/Srikanth-Rudrarapu/firm-lens.git
cd firm-lens
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -e .
```

---

## 3. Reproduction Workflow

To execute the entire empirical suite, trigger the root harness:
```bash
./replication/run_replication.sh
```

Alternatively, invoke modules individually:

### Step 1: Multi-Target Detection Performance (Table I & Fig. 1)
Evaluates rule triggering precision, recall, and F1-score against the N=11 target ground-truth suite:
```bash
python experiments/evaluate_accuracy.py
```
* **Generated Artifacts:**
  * `replication/results/multi_target_accuracy.json`
  * `replication/results/per_cwe_metrics.csv`

### Step 2: Modular Analyzer Ablation Study (Table II & Fig. 4)
Executes leave-one-out modular ablation to quantify individual component contributions:
```bash
python experiments/run_ablation_study.py
```
* **Generated Artifacts:**
  * `replication/results/ablation_study.csv`
  * `replication/results/ablation_study.json`

### Step 3: Latency and Memory Profiling (Figs. 2 & 3)
Measures static scan latency, processing throughput (MB/s), and resident heap memory across 10 trials per target (110 total executions):
```bash
python experiments/benchmark_performance.py
```
* **Generated Artifacts:**
  * `replication/results/performance_trial_data.csv`
  * `replication/results/performance_aggregate_statistics.json`

### Step 4: Dynamic Hardware-in-the-Loop Fault Triage (Section IV-E)
> **Hardware Execution Note:** This step requires physical ESP32 hardware connected via UART. If executed without physical silicon, the pipeline will cleanly bypass this step. Pre-computed telemetry and evaluation metrics from our physical hardware execution are preserved in `replication/results/hil_benchmark_data.csv` and `hil_evaluation_summary.json` for review.
```bash
python experiments/benchmark_hil.py /dev/cu.usbserial-0001 115200
```
* **Generated Artifacts:**
  * `replication/results/hil_benchmark_data.csv`
  * `replication/results/hil_evaluation_summary.json`

---

## 4. Evaluation Corpus Specification (N=11)

| Binary Target | Category | Target Architecture | Image Size | Description |
| :--- | :--- | :--- | :--- | :--- |
| `damn_vuln.bin` | Synthetic / Controlled | ESP32 Xtensa LX6 | 4.0 MB | Injected cryptographic and memory anti-patterns |
| `flash_dump.bin` | Synthetic / Controlled | ESP32 Xtensa LX6 | 4.0 MB | Full flash image with OTA and NVS partition maps |
| `forensic_target_image.bin` | Synthetic / Controlled | ESP32 Xtensa LX6 | 4.0 MB | Insecure URI endpoints and backdoor handlers |
| `full_flash.bin` | Synthetic / Controlled | ESP32 Xtensa LX6 | 4.0 MB | Flash image with unencrypted bootloader headers |
| `hardware_extracted_flash.bin` | Synthetic / Controlled | ESP32 Xtensa LX6 | 4.0 MB | Physical hardware flash extraction image |
| `wifi.bin` | Synthetic / Controlled | ESP32 Xtensa LX6 | 8.8 MB | Compiled application binary image |
| `tasmota32-bluetooth.bin` | Operational OSS | ESP32 Xtensa LX6 | 1.8 MB | Production multi-sensor Bluetooth firmware |
| `tasmota32-display.bin` | Operational OSS | ESP32 Xtensa LX6 | 2.0 MB | Production display driver operational image |
| `tasmota32-ir.bin` | Operational OSS | ESP32 Xtensa LX6 | 1.4 MB | Production infrared control operational image |
| `tasmota32-webcam.bin` | Operational OSS | ESP32 Xtensa LX6 | 2.1 MB | Production camera streaming firmware build |
| `tasmota32c2.bin` | Operational OSS | ESP32-C2 RISC-V | 1.3 MB | Production RISC-V single-core firmware build |

---

## 5. Artifact-to-Paper Cross-Reference

| Manuscript Element | Description | Generating Script | Target Output File |
| :--- | :--- | :--- | :--- |
| **Table I** | Detection Accuracy (N=11) | `evaluate_accuracy.py` | `multi_target_accuracy.json` |
| **Table II** | Modular Component Ablation | `run_ablation_study.py` | `ablation_study.csv` |
| **Table III** | Capability Comparison Matrix | `evaluate_tool_comparison.py` | `tool_comparison_matrix.json` |
| **Fig. 1** | Per-CWE Recall Breakdown | `evaluate_accuracy.py` | `fig_cwe_detection_breakdown.png` |
| **Fig. 2** | Latency vs. Firmware Size | `benchmark_performance.py` | `fig_latency_vs_size.png` |
| **Fig. 3** | Peak Heap Memory Scaling | `benchmark_performance.py` | `fig_memory_vs_size.png` |
| **Fig. 4** | Ablation Recall Degradation | `run_ablation_study.py` | `fig_ablation_recall.png` |

---

## 6. Official Links & Package Distribution

* **PyPI Distribution:** [https://pypi.org/project/firm-lens/](https://pypi.org/project/firm-lens/)
* **Source Repository:** [https://github.com/Srikanth-Rudrarapu/firm-lens](https://github.com/Srikanth-Rudrarapu/firm-lens)

---

## 7. License

This artifact evaluation package is distributed under the MIT License.