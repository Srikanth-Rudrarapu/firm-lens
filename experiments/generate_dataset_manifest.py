#!/usr/bin/env python3
import json
import csv
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = ROOT / "replication" / "test_samples"
RESULTS_DIR = ROOT / "replication" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# 1. Generate exact SHA-256 and Size Manifest
manifest = {"firmware_targets": {}}
for p in sorted(SAMPLES_DIR.glob("*.bin")):
    h = hashlib.sha256(p.read_bytes()).hexdigest()
    size = p.stat().st_size
    manifest["firmware_targets"][p.name] = {
        "sha256": h,
        "size_bytes": size,
        "size_mb": round(size / (1024 * 1024), 2)
    }

with open(RESULTS_DIR / "dataset_sha256_manifest.json", "w") as f:
    json.dump(manifest, f, indent=2)

print(" Regenerated dataset_sha256_manifest.json with exact sizes.")