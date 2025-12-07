#!/usr/bin/env python3
"""
Visualize Purge Events: SUCCESS vs BLOCKED vs SKIP
Shows the percentage of each event type.
"""

import os
import glob
import matplotlib.pyplot as plt
from collections import defaultdict

LOG_DIR = "/Users/devaraja/Downloads/Box64 tick hot"

def count_events():
    """Count all purge event types."""
    log_files = glob.glob(os.path.join(LOG_DIR, "box64_purge_*.log"))
    print(f"Found {len(log_files)} log files")

    counts = defaultdict(int)

    for filepath in log_files:
        with open(filepath, 'r', errors='replace') as f:
            for line in f:
                if '[PURGE SUCCESS]' in line:
                    counts['SUCCESS'] += 1
                elif '[PURGE BLOCKED]' in line:
                    counts['BLOCKED'] += 1
                elif '[PURGE SKIP]' in line:
                    counts['SKIP'] += 1

    return counts

def visualize(counts):
    """Create pie chart showing event distribution."""

    labels = ['SUCCESS', 'BLOCKED', 'SKIP']
    values = [counts[l] for l in labels]
    total = sum(values)

    colors = ['#2ecc71', '#e74c3c', '#f39c12']  # green, red, orange

    fig, ax = plt.subplots(figsize=(10, 6))

    # Pie chart
    wedges, texts, autotexts = ax.pie(
        values,
        labels=labels,
        colors=colors,
        autopct=lambda p: f'{p:.1f}%\n({int(p*total/100):,})',
        startangle=90,
        explode=(0.02, 0.02, 0.02),
        textprops={'fontsize': 11}
    )

    ax.set_title(f'Purge Event Distribution (Total: {total:,} events)\n\n'
                 f'SUCCESS = Purged | BLOCKED = in_used | SKIP = Too young',
                 fontsize=12, fontweight='bold')

    # Add legend with descriptions
    legend_labels = [
        f'SUCCESS: Block purged ({counts["SUCCESS"]:,})',
        f'BLOCKED: in_used=1, cannot purge ({counts["BLOCKED"]:,})',
        f'SKIP: age < threshold ({counts["SKIP"]:,})'
    ]
    ax.legend(wedges, legend_labels, loc='lower center', bbox_to_anchor=(0.5, -0.15))

    plt.tight_layout()

    output_path = os.path.join(LOG_DIR, "purge_event_distribution.png")
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"\nSaved: {output_path}")

    # Print summary
    print("\n" + "="*50)
    print("PURGE EVENT SUMMARY")
    print("="*50)
    print(f"\n{'Event':<12} {'Count':>12} {'Percent':>10}")
    print("-"*35)
    for label in labels:
        pct = counts[label] / total * 100 if total > 0 else 0
        print(f"{label:<12} {counts[label]:>12,} {pct:>9.1f}%")
    print("-"*35)
    print(f"{'TOTAL':<12} {total:>12,} {100.0:>9.1f}%")

    # Failed = BLOCKED + SKIP
    failed = counts['BLOCKED'] + counts['SKIP']
    failed_pct = failed / total * 100 if total > 0 else 0
    print(f"\n{'FAILED':<12} {failed:>12,} {failed_pct:>9.1f}%  (BLOCKED + SKIP)")
    print(f"{'SUCCESS':<12} {counts['SUCCESS']:>12,} {counts['SUCCESS']/total*100:>9.1f}%")

def main():
    print("="*50)
    print("Purge Event Analysis")
    print("="*50)

    counts = count_events()
    visualize(counts)

if __name__ == "__main__":
    main()
