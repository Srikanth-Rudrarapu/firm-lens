import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os

# Ensure the figures directory exists
os.makedirs('replication/results/figures', exist_ok=True)

# ==========================================
# Figure 1: CWE Detection
# ==========================================
try:
    df_cwe = pd.read_csv('replication/results/per_cwe_metrics.csv')
    cwe_col = df_cwe.columns[0]
    recall_col = df_cwe.columns[-1]
    
    # Ensure numeric types for the y-axis
    df_cwe[recall_col] = pd.to_numeric(df_cwe[recall_col])
    
    plt.figure(figsize=(10, 5), dpi=300)
    plt.bar(df_cwe[cwe_col], df_cwe[recall_col], color='#3498db', edgecolor='black', width=0.5)
    
    plt.ylabel('Recall (%)', fontsize=11)
    plt.xlabel('Common Weakness Enumeration (CWE)', fontsize=11)
    plt.title('Empirical Detection Rate per Target CWE Class', fontweight='bold', fontsize=14)
    plt.ylim(0, 115)
    plt.xticks(rotation=45, ha='right', fontsize=11)
    plt.grid(axis='y', linestyle=':', alpha=0.7)
    
    plt.tight_layout()
    plt.savefig('replication/results/figures/fig_cwe_detection_breakdown.png')
    print(" Regenerated Figure 1: CWE Detection Breakdown")
except Exception as e: 
    print(f"Error generating CWE Plot: {e}")

# ==========================================
# Figure 4: Ablation Study
# ==========================================
try:
    df_ablation = pd.read_csv('replication/results/ablation_study.csv')
    
    # Sort for visual hierarchy (Baseline at top)
    df_ablation['is_baseline'] = df_ablation['configuration'].str.contains('Baseline')
    df_ablation = df_ablation.sort_values(['is_baseline', 'recall_pct'], ascending=[False, True])
    
    plt.figure(figsize=(10, 5), dpi=300)
    
    # Plot bars (Red for ablation, Blue for baseline)
    colors = ['tab:blue' if b else 'tab:red' for b in df_ablation['is_baseline']]
    bars = plt.barh(df_ablation['configuration'], df_ablation['recall_pct'], 
                    color=colors, edgecolor='black', height=0.6)
    
    plt.xlabel('Empirical Recall (%)', fontsize=11)
    plt.title('Modular Analyzer Ablation Study: Impact on Benchmark Recall (%)', fontweight='bold', fontsize=12)
    plt.xlim(60, 105)
    plt.grid(axis='x', linestyle=':', alpha=0.7)
    
    # Add percentage labels
    for bar in bars:
        plt.text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2, 
                 f'{bar.get_width():.1f}%', va='center', fontweight='bold', fontsize=10)
    
    # Add vertical line at 100%
    plt.axvline(100, color='grey', linestyle=':')
    
    plt.tight_layout()
    plt.savefig('replication/results/figures/fig_ablation_recall.png')
    print(" Regenerated Figure 4: Ablation Recall Degradation")
except Exception as e: 
    print(f"Error generating Ablation Plot: {e}")

# ==========================================
# Figures 2 & 3: Performance Metrics
# ==========================================
try:
    df = pd.read_csv('replication/results/performance_benchmark.csv')
    
    # Dynamically find the correct columns
    size_col = next(c for c in df.columns if 'size' in c.lower())
    lat_col = next(c for c in df.columns if 'latency' in c.lower() or 'mean' in c.lower() or 'time' in c.lower())
    mem_col = next(c for c in df.columns if 'ram' in c.lower() or 'mem' in c.lower())
    
    x_line = np.linspace(df[size_col].min(), df[size_col].max(), 100)
    
    # Figure 2: Latency Plot
    plt.figure(figsize=(8, 5), dpi=300)
    plt.scatter(df[size_col], df[lat_col], s=100, color='tab:blue', edgecolor='black', zorder=3)
    
    z = np.polyfit(df[size_col], df[lat_col], 1)
    p = np.poly1d(z)
    plt.plot(x_line, p(x_line), color='tab:red', linestyle='--', label=f"Linear Fit (Slope: {z[0]:.3f} s/MB)")
    
    plt.xlabel('Firmware Image Size (MB)', fontsize=11)
    plt.ylabel('Mean Analysis Latency (Seconds)', fontsize=11)
    plt.title('FirmLens Static Analysis Latency vs. Firmware Size', fontweight='bold', fontsize=12)
    plt.legend()
    plt.grid(linestyle=':', alpha=0.7)
    plt.tight_layout()
    plt.savefig('replication/results/figures/fig_latency_vs_size.png')
    print(" Regenerated Figure 2: Static Analysis Latency")
    
    # Figure 3: Memory Plot
    plt.figure(figsize=(8, 5), dpi=300)
    plt.scatter(df[size_col], df[mem_col], s=100, color='tab:green', edgecolor='black', zorder=3)
    
    z_mem = np.polyfit(df[size_col], df[mem_col], 1)
    p_mem = np.poly1d(z_mem)
    plt.plot(x_line, p_mem(x_line), color='tab:orange', linestyle='--', label=f"Linear Fit ({z_mem[0]:.2f} MB RAM / Flash MB)")
    
    plt.xlabel('Firmware Image Size (MB)', fontsize=11)
    plt.ylabel('Peak Heap Memory (MB)', fontsize=11)
    plt.title('FirmLens Peak Memory Usage vs. Firmware Size', fontweight='bold', fontsize=12)
    plt.legend()
    plt.grid(linestyle=':', alpha=0.7)
    plt.tight_layout()
    plt.savefig('replication/results/figures/fig_memory_vs_size.png')
    print(" Regenerated Figure 3: Peak Memory Usage")
    
except Exception as e: 
    print(f"Error generating Performance Plots: {e}")