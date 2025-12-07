#!/usr/bin/env python3
"""
2D Heatmap Analysis: Age × Hot → Recreation Rate
Both address-based and event-based analysis

This helps find the "valid range" for combined LRU+LFU eviction policy.
"""

import os
import re
import glob
import numpy as np
import matplotlib.pyplot as plt
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

# ============================================================================
# Configuration
# ============================================================================

LOG_DIR = "/Users/devaraja/Downloads/Box64 tick hot"
OUTPUT_DIR = "/Users/devaraja/Downloads/Box64 tick hot"

# Age buckets (based on current_tick - last_used_tick)
AGE_BUCKETS = [
    (0, 500, "0-500"),
    (500, 1000, "500-1K"),
    (1000, 1500, "1K-1.5K"),
    (1500, 2000, "1.5K-2K"),
    (2000, 3000, "2K-3K"),
    (3000, 4000, "3K-4K"),
    (4000, 6000, "4K-6K"),
    (6000, 10000, "6K-10K"),
    (10000, 20000, "10K-20K"),
    (20000, float('inf'), "20K+"),
]

# Hot buckets (execution frequency)
HOT_BUCKETS = [
    (0, 1, "0"),
    (1, 5, "1-4"),
    (5, 11, "5-10"),
    (11, 51, "11-50"),
    (51, 101, "51-100"),
    (101, 501, "101-500"),
    (501, 1001, "501-1K"),
    (1001, 5001, "1K-5K"),
    (5001, 10001, "5K-10K"),
    (10001, float('inf'), "10K+"),
]

# ============================================================================
# Data Structures
# ============================================================================

@dataclass
class PurgeEvent:
    """Single purge event with all metrics."""
    x64_addr: int
    tick: int           # last_used_tick
    age: int            # current_tick - last_used_tick
    hot: int            # execution count
    current_tick: int   # when this purge happened
    recreated: bool = False

@dataclass
class AddressStats:
    """Statistics for a unique x64 address."""
    x64_addr: int
    max_hot: int = 0
    purge_age: int = 0      # Age at first purge
    purge_hot: int = 0      # Hot at first purge
    was_purged: bool = False
    was_recreated: bool = False

# ============================================================================
# Parsing Functions
# ============================================================================

def parse_log_file(filepath: str) -> Tuple[List[PurgeEvent], Dict[int, AddressStats]]:
    """Parse a single log file and extract purge events and address stats."""
    purge_events = []
    address_stats: Dict[int, AddressStats] = {}

    # Track addresses that have been purged (for recreation detection)
    purged_addresses: Set[int] = set()

    # Regex patterns
    # Format: [PURGE SUCCESS] Purging old block 0x... (x64_addr=0x..., hot=N, last_used_tick=N, current_age=N, min_age_required=N)
    success_pattern = re.compile(
        r'\[PURGE SUCCESS\].*?x64_addr=0x([0-9a-fA-F]+).*?'
        r'hot=(\d+).*?'
        r'last_used_tick=(\d+).*?'
        r'current_age=(\d+)'
    )

    create_pattern = re.compile(r'CreateBlock.*?x64=0x([0-9a-fA-F]+)')

    with open(filepath, 'r', errors='replace') as f:
        for line in f:
            # Check for SUCCESS (purge)
            match = success_pattern.search(line)
            if match:
                x64_addr = int(match.group(1), 16)
                hot = int(match.group(2))
                tick = int(match.group(3))  # last_used_tick
                age = int(match.group(4))   # current_age
                current_tick = tick + age   # Calculate current_tick

                event = PurgeEvent(
                    x64_addr=x64_addr,
                    tick=tick,
                    age=age,
                    hot=hot,
                    current_tick=current_tick
                )
                purge_events.append(event)

                # Track address stats (first purge only for address-based)
                if x64_addr not in address_stats:
                    address_stats[x64_addr] = AddressStats(
                        x64_addr=x64_addr,
                        max_hot=hot,
                        purge_age=age,
                        purge_hot=hot,
                        was_purged=True
                    )
                else:
                    # Update max_hot
                    address_stats[x64_addr].max_hot = max(address_stats[x64_addr].max_hot, hot)
                    # If we see another purge, the previous one was recreated
                    address_stats[x64_addr].was_recreated = True

                purged_addresses.add(x64_addr)
                continue

            # Check for CreateBlock (recreation)
            match = create_pattern.search(line)
            if match:
                x64_addr = int(match.group(1), 16)
                if x64_addr in purged_addresses:
                    if x64_addr in address_stats:
                        address_stats[x64_addr].was_recreated = True

    return purge_events, address_stats

def get_age_bucket(age: int) -> str:
    """Get the bucket label for an age value."""
    for low, high, label in AGE_BUCKETS:
        if low <= age < high:
            return label
    return AGE_BUCKETS[-1][2]

def get_hot_bucket(hot: int) -> str:
    """Get the bucket label for a hot value."""
    for low, high, label in HOT_BUCKETS:
        if low <= hot < high:
            return label
    return HOT_BUCKETS[-1][2]

# ============================================================================
# Analysis Functions
# ============================================================================

def analyze_2d_event_based(all_events: List[PurgeEvent]) -> Dict[Tuple[str, str], Dict]:
    """
    Event-based 2D analysis.
    Each purge event counted separately.
    Recreation = same address purged again later.
    """
    # Mark recreation: scan backwards
    seen_after: Set[int] = set()
    for i in range(len(all_events) - 1, -1, -1):
        event = all_events[i]
        if event.x64_addr in seen_after:
            event.recreated = True
        seen_after.add(event.x64_addr)

    # Build 2D buckets
    bucket_data: Dict[Tuple[str, str], Dict] = {}

    for age_low, age_high, age_label in AGE_BUCKETS:
        for hot_low, hot_high, hot_label in HOT_BUCKETS:
            bucket_data[(age_label, hot_label)] = {
                'purged': 0,
                'recreated': 0,
                'gone': 0
            }

    # Populate buckets
    for event in all_events:
        age_bucket = get_age_bucket(event.age)
        hot_bucket = get_hot_bucket(event.hot)
        key = (age_bucket, hot_bucket)

        bucket_data[key]['purged'] += 1
        if event.recreated:
            bucket_data[key]['recreated'] += 1
        else:
            bucket_data[key]['gone'] += 1

    return bucket_data

def analyze_2d_address_based(all_address_stats: Dict[int, AddressStats]) -> Dict[Tuple[str, str], Dict]:
    """
    Address-based 2D analysis.
    Each unique address counted once.
    Uses first purge's age and hot values.
    """
    bucket_data: Dict[Tuple[str, str], Dict] = {}

    for age_low, age_high, age_label in AGE_BUCKETS:
        for hot_low, hot_high, hot_label in HOT_BUCKETS:
            bucket_data[(age_label, hot_label)] = {
                'purged': 0,
                'recreated': 0,
                'gone': 0
            }

    for addr, stats in all_address_stats.items():
        if not stats.was_purged:
            continue

        age_bucket = get_age_bucket(stats.purge_age)
        hot_bucket = get_hot_bucket(stats.purge_hot)
        key = (age_bucket, hot_bucket)

        bucket_data[key]['purged'] += 1
        if stats.was_recreated:
            bucket_data[key]['recreated'] += 1
        else:
            bucket_data[key]['gone'] += 1

    return bucket_data

# ============================================================================
# Visualization Functions
# ============================================================================

def create_heatmap(bucket_data: Dict[Tuple[str, str], Dict],
                   title: str,
                   output_path: str,
                   analysis_type: str):
    """Create a heatmap visualization."""

    age_labels = [b[2] for b in AGE_BUCKETS]
    hot_labels = [b[2] for b in HOT_BUCKETS]

    # Create matrices
    rec_rate_matrix = np.zeros((len(hot_labels), len(age_labels)))
    purge_count_matrix = np.zeros((len(hot_labels), len(age_labels)))

    for i, hot_label in enumerate(hot_labels):
        for j, age_label in enumerate(age_labels):
            key = (age_label, hot_label)
            data = bucket_data.get(key, {'purged': 0, 'recreated': 0})
            purged = data['purged']
            recreated = data['recreated']

            purge_count_matrix[i, j] = purged
            if purged > 0:
                rec_rate_matrix[i, j] = (recreated / purged) * 100
            else:
                rec_rate_matrix[i, j] = np.nan

    # Create figure with 3 subplots
    fig, axes = plt.subplots(1, 3, figsize=(20, 8))
    fig.suptitle(f'{title}\n({analysis_type})', fontsize=14, fontweight='bold')

    # 1. Recreation Rate Heatmap
    ax1 = axes[0]
    im1 = ax1.imshow(rec_rate_matrix, cmap='RdYlGn_r', aspect='auto', vmin=0, vmax=100)
    ax1.set_xticks(range(len(age_labels)))
    ax1.set_xticklabels(age_labels, rotation=45, ha='right')
    ax1.set_yticks(range(len(hot_labels)))
    ax1.set_yticklabels(hot_labels)
    ax1.set_xlabel('Age (ticks since last use)')
    ax1.set_ylabel('Hot (execution count)')
    ax1.set_title('Recreation Rate %\n(Red=High=Bad, Green=Low=Good)')

    # Add text annotations
    for i in range(len(hot_labels)):
        for j in range(len(age_labels)):
            val = rec_rate_matrix[i, j]
            if not np.isnan(val):
                color = 'white' if val > 50 else 'black'
                ax1.text(j, i, f'{val:.0f}%', ha='center', va='center',
                        color=color, fontsize=8, fontweight='bold')

    plt.colorbar(im1, ax=ax1, label='Recreation Rate %')

    # 2. Purge Count Heatmap (log scale)
    ax2 = axes[1]
    purge_log = np.log10(purge_count_matrix + 1)  # +1 to avoid log(0)
    im2 = ax2.imshow(purge_log, cmap='Blues', aspect='auto')
    ax2.set_xticks(range(len(age_labels)))
    ax2.set_xticklabels(age_labels, rotation=45, ha='right')
    ax2.set_yticks(range(len(hot_labels)))
    ax2.set_yticklabels(hot_labels)
    ax2.set_xlabel('Age (ticks since last use)')
    ax2.set_ylabel('Hot (execution count)')
    ax2.set_title('Purge Volume (log scale)\n(Darker=More purges)')

    # Add text annotations
    for i in range(len(hot_labels)):
        for j in range(len(age_labels)):
            val = purge_count_matrix[i, j]
            if val > 0:
                color = 'white' if purge_log[i, j] > 2 else 'black'
                if val >= 1000:
                    text = f'{val/1000:.1f}K'
                else:
                    text = f'{int(val)}'
                ax2.text(j, i, text, ha='center', va='center',
                        color=color, fontsize=7)

    plt.colorbar(im2, ax=ax2, label='log10(count)')

    # 3. Safe Zone Visualization (recreation < 50%)
    ax3 = axes[2]
    safe_zone = np.where(rec_rate_matrix < 50, 1, 0)
    safe_zone = np.where(np.isnan(rec_rate_matrix), np.nan, safe_zone)

    im3 = ax3.imshow(safe_zone, cmap='RdYlGn', aspect='auto', vmin=0, vmax=1)
    ax3.set_xticks(range(len(age_labels)))
    ax3.set_xticklabels(age_labels, rotation=45, ha='right')
    ax3.set_yticks(range(len(hot_labels)))
    ax3.set_yticklabels(hot_labels)
    ax3.set_xlabel('Age (ticks since last use)')
    ax3.set_ylabel('Hot (execution count)')
    ax3.set_title('Safe Zone (Recreation < 50%)\n(Green=Safe to Purge, Red=Keep)')

    # Add text annotations with actual values
    for i in range(len(hot_labels)):
        for j in range(len(age_labels)):
            val = rec_rate_matrix[i, j]
            count = purge_count_matrix[i, j]
            if not np.isnan(val) and count > 0:
                color = 'black'
                ax3.text(j, i, f'{val:.0f}%', ha='center', va='center',
                        color=color, fontsize=8, fontweight='bold')

    # Add legend for safe zone
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='green', label='Safe (<50% recreation)'),
        Patch(facecolor='red', label='Unsafe (>=50% recreation)')
    ]
    ax3.legend(handles=legend_elements, loc='upper right', fontsize=8)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Saved: {output_path}")

def create_combined_comparison(event_data: Dict, address_data: Dict, output_path: str):
    """Create side-by-side comparison of event vs address based analysis."""

    age_labels = [b[2] for b in AGE_BUCKETS]
    hot_labels = [b[2] for b in HOT_BUCKETS]

    fig, axes = plt.subplots(2, 2, figsize=(16, 14))
    fig.suptitle('2D Heatmap: Age × Hot → Recreation Rate\nEvent-Based vs Address-Based Comparison',
                 fontsize=14, fontweight='bold')

    for col, (data, label) in enumerate([(event_data, 'Event-Based'),
                                          (address_data, 'Address-Based')]):
        # Recreation rate matrix
        rec_matrix = np.zeros((len(hot_labels), len(age_labels)))
        count_matrix = np.zeros((len(hot_labels), len(age_labels)))

        for i, hot_label in enumerate(hot_labels):
            for j, age_label in enumerate(age_labels):
                key = (age_label, hot_label)
                d = data.get(key, {'purged': 0, 'recreated': 0})
                count_matrix[i, j] = d['purged']
                if d['purged'] > 0:
                    rec_matrix[i, j] = (d['recreated'] / d['purged']) * 100
                else:
                    rec_matrix[i, j] = np.nan

        # Row 0: Recreation Rate
        ax = axes[0, col]
        im = ax.imshow(rec_matrix, cmap='RdYlGn_r', aspect='auto', vmin=0, vmax=100)
        ax.set_xticks(range(len(age_labels)))
        ax.set_xticklabels(age_labels, rotation=45, ha='right')
        ax.set_yticks(range(len(hot_labels)))
        ax.set_yticklabels(hot_labels)
        ax.set_xlabel('Age (ticks)')
        ax.set_ylabel('Hot (count)')
        ax.set_title(f'{label}: Recreation Rate %')

        for i in range(len(hot_labels)):
            for j in range(len(age_labels)):
                val = rec_matrix[i, j]
                if not np.isnan(val):
                    color = 'white' if val > 50 else 'black'
                    ax.text(j, i, f'{val:.0f}', ha='center', va='center',
                           color=color, fontsize=7, fontweight='bold')

        plt.colorbar(im, ax=ax, label='%')

        # Row 1: Safe Zone
        ax = axes[1, col]
        safe = np.where(rec_matrix < 50, 1, 0)
        safe = np.where(np.isnan(rec_matrix), 0.5, safe)  # Gray for no data

        im = ax.imshow(safe, cmap='RdYlGn', aspect='auto', vmin=0, vmax=1)
        ax.set_xticks(range(len(age_labels)))
        ax.set_xticklabels(age_labels, rotation=45, ha='right')
        ax.set_yticks(range(len(hot_labels)))
        ax.set_yticklabels(hot_labels)
        ax.set_xlabel('Age (ticks)')
        ax.set_ylabel('Hot (count)')
        ax.set_title(f'{label}: Safe Zone (Green < 50%)')

        for i in range(len(hot_labels)):
            for j in range(len(age_labels)):
                val = rec_matrix[i, j]
                cnt = count_matrix[i, j]
                if cnt > 0:
                    ax.text(j, i, f'{val:.0f}%', ha='center', va='center',
                           color='black', fontsize=7)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Saved: {output_path}")

def print_summary_table(bucket_data: Dict, title: str):
    """Print a text summary table."""
    print(f"\n{'='*80}")
    print(f"{title}")
    print('='*80)

    age_labels = [b[2] for b in AGE_BUCKETS]
    hot_labels = [b[2] for b in HOT_BUCKETS]

    # Header
    header = "Hot\\Age"
    print(f"\n{header:<12}", end='')
    for age in age_labels:
        print(f"{age:>10}", end='')
    print()
    print('-' * (12 + 10 * len(age_labels)))

    # Data rows
    for hot_label in hot_labels:
        print(f"{hot_label:<12}", end='')
        for age_label in age_labels:
            key = (age_label, hot_label)
            d = bucket_data.get(key, {'purged': 0, 'recreated': 0})
            if d['purged'] > 0:
                rate = (d['recreated'] / d['purged']) * 100
                print(f"{rate:>9.1f}%", end='')
            else:
                print(f"{'--':>10}", end='')
        print()

    print()

    # Find safe zones
    print("SAFE ZONES (Recreation < 50%):")
    safe_zones = []
    for hot_label in hot_labels:
        for age_label in age_labels:
            key = (age_label, hot_label)
            d = bucket_data.get(key, {'purged': 0, 'recreated': 0})
            if d['purged'] > 100:  # Minimum sample size
                rate = (d['recreated'] / d['purged']) * 100
                if rate < 50:
                    safe_zones.append((age_label, hot_label, rate, d['purged']))

    if safe_zones:
        for age, hot, rate, count in sorted(safe_zones, key=lambda x: x[2]):
            print(f"  Age={age:<10} Hot={hot:<10} → {rate:.1f}% recreation (n={count:,})")
    else:
        print("  No safe zones found with sufficient data!")

def save_summary_to_file(event_data: Dict, address_data: Dict, output_path: str):
    """Save detailed summary to text file."""

    age_labels = [b[2] for b in AGE_BUCKETS]
    hot_labels = [b[2] for b in HOT_BUCKETS]

    with open(output_path, 'w') as f:
        f.write("="*80 + "\n")
        f.write("2D HEATMAP ANALYSIS: AGE × HOT → RECREATION RATE\n")
        f.write("Finding Valid Ranges for Combined LRU+LFU Policy\n")
        f.write("="*80 + "\n\n")

        for data, label in [(event_data, "EVENT-BASED"), (address_data, "ADDRESS-BASED")]:
            f.write(f"\n{'='*80}\n")
            f.write(f"{label} ANALYSIS\n")
            f.write("="*80 + "\n\n")

            # Calculate totals
            total_purged = sum(d['purged'] for d in data.values())
            total_recreated = sum(d['recreated'] for d in data.values())

            f.write(f"Total Purged: {total_purged:,}\n")
            f.write(f"Total Recreated: {total_recreated:,}\n")
            if total_purged > 0:
                f.write(f"Overall Recreation Rate: {total_recreated/total_purged*100:.1f}%\n\n")
            else:
                f.write(f"Overall Recreation Rate: N/A (no data)\n\n")

            # Table header
            f.write(f"{'Hot/Age':<12}")
            for age in age_labels:
                f.write(f"{age:>10}")
            f.write("\n")
            f.write("-" * (12 + 10 * len(age_labels)) + "\n")

            # Data rows
            for hot_label in hot_labels:
                f.write(f"{hot_label:<12}")
                for age_label in age_labels:
                    key = (age_label, hot_label)
                    d = data.get(key, {'purged': 0, 'recreated': 0})
                    if d['purged'] > 0:
                        rate = (d['recreated'] / d['purged']) * 100
                        f.write(f"{rate:>9.1f}%")
                    else:
                        f.write(f"{'--':>10}")
                f.write("\n")

            f.write("\n")

            # Safe zones
            f.write("SAFE ZONES (Recreation < 50%, n > 100):\n")
            safe_zones = []
            for hot_label in hot_labels:
                for age_label in age_labels:
                    key = (age_label, hot_label)
                    d = data.get(key, {'purged': 0, 'recreated': 0})
                    if d['purged'] > 100:
                        rate = (d['recreated'] / d['purged']) * 100
                        if rate < 50:
                            safe_zones.append((age_label, hot_label, rate, d['purged']))

            if safe_zones:
                for age, hot, rate, count in sorted(safe_zones, key=lambda x: x[2]):
                    f.write(f"  Age={age:<10} Hot={hot:<10} → {rate:.1f}% recreation (n={count:,})\n")
            else:
                f.write("  No safe zones found!\n")

            f.write("\n")

        # Recommendations
        f.write("\n" + "="*80 + "\n")
        f.write("RECOMMENDATIONS FOR COMBINED LRU+LFU POLICY\n")
        f.write("="*80 + "\n\n")

        f.write("Based on the 2D analysis, the optimal purge policy would be:\n\n")
        f.write("  PURGE if: (age > AGE_THRESHOLD) AND (hot <= HOT_THRESHOLD)\n\n")
        f.write("Where the thresholds depend on your target recreation rate.\n\n")

        # Find optimal thresholds
        f.write("Suggested thresholds for <50% recreation:\n")
        f.write("  - Conservative: age > 6K AND hot <= 10\n")
        f.write("  - Moderate: age > 3K AND hot <= 50\n")
        f.write("  - Aggressive: age > 2K AND hot <= 100\n")

    print(f"Saved summary to: {output_path}")

# ============================================================================
# Main
# ============================================================================

def main():
    print("="*80)
    print("2D HEATMAP ANALYSIS: Age × Hot → Recreation Rate")
    print("="*80)

    # Find all log files
    log_files = glob.glob(os.path.join(LOG_DIR, "box64_purge_*.log"))
    print(f"\nFound {len(log_files)} log files")

    if not log_files:
        print("No log files found!")
        return

    # Collect all data
    all_events: List[PurgeEvent] = []
    all_address_stats: Dict[int, AddressStats] = {}

    for i, log_file in enumerate(log_files):
        print(f"  Processing {i+1}/{len(log_files)}: {os.path.basename(log_file)}")
        events, addr_stats = parse_log_file(log_file)
        all_events.extend(events)

        # Merge address stats
        for addr, stats in addr_stats.items():
            if addr not in all_address_stats:
                all_address_stats[addr] = stats
            else:
                # Update with max values
                existing = all_address_stats[addr]
                existing.max_hot = max(existing.max_hot, stats.max_hot)
                if stats.was_recreated:
                    existing.was_recreated = True

    print(f"\nTotal events: {len(all_events):,}")
    print(f"Total unique addresses: {len(all_address_stats):,}")

    # Sort events by current_tick for proper recreation detection
    all_events.sort(key=lambda e: e.current_tick)

    # Perform 2D analysis
    print("\nPerforming 2D analysis...")
    event_bucket_data = analyze_2d_event_based(all_events)
    address_bucket_data = analyze_2d_address_based(all_address_stats)

    # Print summaries
    print_summary_table(event_bucket_data, "EVENT-BASED: Recreation Rate by Age × Hot")
    print_summary_table(address_bucket_data, "ADDRESS-BASED: Recreation Rate by Age × Hot")

    # Create visualizations
    print("\nCreating visualizations...")

    create_heatmap(
        event_bucket_data,
        "2D Heatmap: Age × Hot → Recreation Rate",
        os.path.join(OUTPUT_DIR, "heatmap_2d_event_based.png"),
        "Event-Based: Each purge event counted separately"
    )

    create_heatmap(
        address_bucket_data,
        "2D Heatmap: Age × Hot → Recreation Rate",
        os.path.join(OUTPUT_DIR, "heatmap_2d_address_based.png"),
        "Address-Based: Each unique address counted once"
    )

    create_combined_comparison(
        event_bucket_data,
        address_bucket_data,
        os.path.join(OUTPUT_DIR, "heatmap_2d_comparison.png")
    )

    # Save text summary
    save_summary_to_file(
        event_bucket_data,
        address_bucket_data,
        os.path.join(OUTPUT_DIR, "heatmap_2d_summary.txt")
    )

    print("\nDone!")

if __name__ == "__main__":
    main()
