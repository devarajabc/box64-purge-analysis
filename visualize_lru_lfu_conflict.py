#!/usr/bin/env python3
"""
Visualize LRU vs LFU Conflict Zone

Shows: When LRU purges blocks that are HOT (high frequency)
- X-axis: Age (LRU metric)
- Y-axis: Count of purged blocks
- Colors: Cold vs Hot blocks

This reveals where LRU is WRONG - purging valuable hot code.
"""

import os
import re
import glob
import numpy as np
import matplotlib.pyplot as plt
from collections import defaultdict

LOG_DIR = "/Users/devaraja/Downloads/Box64 tick hot"

# Age buckets (LRU)
AGE_BUCKETS = [
    (1000, 1500, "1K-1.5K"),
    (1500, 2000, "1.5K-2K"),
    (2000, 3000, "2K-3K"),
    (3000, 4000, "3K-4K"),
    (4000, 6000, "4K-6K"),
    (6000, 10000, "6K-10K"),
    (10000, 20000, "10K-20K"),
    (20000, float('inf'), "20K+"),
]

# Hot thresholds (LFU)
HOT_COLD = 10       # hot <= 10 = COLD (safe to purge)
HOT_WARM = 100      # hot 11-100 = WARM (borderline)
# hot > 100 = HOT (should NOT purge)

def get_age_bucket(age):
    for low, high, label in AGE_BUCKETS:
        if low <= age < high:
            return label
    return None

def parse_logs():
    """Parse all log files and collect purge events."""
    log_files = glob.glob(os.path.join(LOG_DIR, "box64_purge_*.log"))
    print(f"Found {len(log_files)} log files")

    # Data structure: age_bucket -> {cold, warm, hot} counts
    data = defaultdict(lambda: {'cold': 0, 'warm': 0, 'hot': 0})

    pattern = re.compile(
        r'\[PURGE SUCCESS\].*?'
        r'hot=(\d+).*?'
        r'last_used_tick=(\d+).*?'
        r'current_age=(\d+)'
    )

    total_events = 0
    for filepath in log_files:
        with open(filepath, 'r', errors='replace') as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    hot = int(match.group(1))
                    age = int(match.group(3))

                    bucket = get_age_bucket(age)
                    if bucket is None:
                        continue

                    total_events += 1

                    if hot <= HOT_COLD:
                        data[bucket]['cold'] += 1
                    elif hot <= HOT_WARM:
                        data[bucket]['warm'] += 1
                    else:
                        data[bucket]['hot'] += 1

    print(f"Total purge events: {total_events:,}")
    return data

def visualize(data):
    """Create visualization showing LRU vs LFU conflict."""

    labels = [b[2] for b in AGE_BUCKETS]
    cold = [data[label]['cold'] for label in labels]
    warm = [data[label]['warm'] for label in labels]
    hot = [data[label]['hot'] for label in labels]

    totals = [c + w + h for c, w, h in zip(cold, warm, hot)]
    hot_pct = [h / t * 100 if t > 0 else 0 for h, t in zip(hot, totals)]

    fig, ax = plt.subplots(figsize=(10, 6))
    fig.suptitle('LRU vs LFU: Purge Events by Age (Event-Based)\n(Red = HOT blocks that LRU should NOT purge)',
                 fontsize=13, fontweight='bold')

    x = np.arange(len(labels))
    width = 0.7

    # Stacked bar chart (counts)
    ax.bar(x, cold, width, label=f'COLD (hot ≤ {HOT_COLD}) - Safe to purge', color='#2ecc71')
    ax.bar(x, warm, width, bottom=cold, label=f'WARM (hot {HOT_COLD+1}-{HOT_WARM}) - Borderline', color='#f39c12')
    ax.bar(x, hot, width, bottom=[c+w for c,w in zip(cold, warm)],
            label=f'HOT (hot > {HOT_WARM}) - Should NOT purge!', color='#e74c3c')

    ax.set_xlabel('Age (ticks since last use)')
    ax.set_ylabel('Number of Purge Events')
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha='right')
    ax.legend(loc='upper right')
    ax.grid(axis='y', alpha=0.3)

    # Add count labels on bars
    for i, (c, w, h) in enumerate(zip(cold, warm, hot)):
        total = c + w + h
        if total > 0:
            ax.text(i, total + 50000, f'{total/1000:.0f}K', ha='center', fontsize=9)

    plt.tight_layout()

    output_path = os.path.join(LOG_DIR, "lru_lfu_conflict.png")
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"\nSaved: {output_path}")

    # Print summary
    print("\n" + "="*60)
    print("LRU vs LFU CONFLICT SUMMARY")
    print("="*60)
    print(f"\nHot threshold: > {HOT_WARM}")
    print(f"Cold threshold: ≤ {HOT_COLD}")
    print()
    print(f"{'Age':<12} {'Total':>10} {'Cold':>10} {'Warm':>10} {'HOT':>10} {'HOT%':>8}")
    print("-"*60)

    total_all = sum(totals)
    total_hot = sum(hot)

    for i, label in enumerate(labels):
        t = totals[i]
        if t > 0:
            print(f"{label:<12} {t:>10,} {cold[i]:>10,} {warm[i]:>10,} {hot[i]:>10,} {hot_pct[i]:>7.1f}%")

    print("-"*60)
    print(f"{'TOTAL':<12} {total_all:>10,} {sum(cold):>10,} {sum(warm):>10,} {total_hot:>10,} {total_hot/total_all*100:>7.1f}%")
    print()
    print(f"FINDING: {total_hot:,} HOT blocks ({total_hot/total_all*100:.1f}%) were purged by LRU")
    print(f"         These blocks should have been protected by LFU!")

def main():
    print("="*60)
    print("LRU vs LFU Conflict Analysis")
    print("="*60)

    data = parse_logs()
    visualize(data)

if __name__ == "__main__":
    main()
