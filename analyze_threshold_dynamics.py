#!/usr/bin/env python3
"""
Box64 Dynamic Threshold Analysis

Analyzes existing purge logs to inform dynamic threshold design.

IMPORTANT: Statistics are ADDRESS-BASED, not event-based.
Each unique x64_addr is counted once based on its overall fate.

Key Questions:
1. What is the age distribution? (CDF of ages)
2. What is the recreation rate? (blocks purged then recreated)
3. How would different thresholds affect purge success rate?
4. What feedback signals can drive threshold adjustment?
"""

import os
import re
import glob
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import statistics

@dataclass
class BlockHistory:
    """Tracks complete history of a single x64_addr."""
    x64_addr: int
    success_count: int = 0
    skip_count: int = 0
    blocked_count: int = 0
    min_age_at_success: int = 999999999  # minimum age when successfully purged
    ages: List[int] = field(default_factory=list)  # all ages observed
    recreations: int = 0  # times we saw this addr after a purge
    last_was_success: bool = False  # track for recreation detection
    max_hot: int = 0

def parse_line(line: str) -> Optional[Tuple[str, int, int, int, int]]:
    """Parse a log line, return (event_type, x64_addr, hot, tick, age) or None."""

    if '[PURGE SUCCESS]' in line:
        event_type = 'SUCCESS'
    elif '[PURGE SKIP]' in line:
        event_type = 'SKIP'
    elif '[PURGE BLOCKED]' in line:
        event_type = 'BLOCKED'
    else:
        return None

    addr_match = re.search(r'x64_addr=(0x[0-9a-fA-F]+)', line)
    hot_match = re.search(r'hot=(\d+)', line)
    tick_match = re.search(r'last_used_tick=(\d+)', line)
    age_match = re.search(r'current_age=(\d+)', line)

    if not addr_match or not hot_match:
        return None

    x64_addr = int(addr_match.group(1), 16)
    hot = int(hot_match.group(1))
    tick = int(tick_match.group(1)) if tick_match else 0
    age = int(age_match.group(1)) if age_match else 0

    return (event_type, x64_addr, hot, tick, age)


def analyze_for_dynamic_threshold(directory: str):
    """Main analysis function."""

    print(f"=== DYNAMIC THRESHOLD ANALYSIS (ADDRESS-BASED) ===\n")
    print(f"Scanning directory: {directory}\n")

    # Find all log files
    log_files = glob.glob(os.path.join(directory, "box64_purge_*.log"))
    log_files = sorted(log_files, key=lambda x: os.path.getsize(x))

    if not log_files:
        print("No log files found!")
        return

    print(f"Found {len(log_files)} log files\n")

    # Per-address tracking
    addresses: Dict[int, BlockHistory] = {}

    # Event counts (for comparison)
    event_counts = {'SUCCESS': 0, 'SKIP': 0, 'BLOCKED': 0}

    # Process files
    total_lines = 0
    for file_idx, filepath in enumerate(log_files, 1):
        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)
        filesize_mb = filesize / (1024 * 1024)

        print(f"[{file_idx}/{len(log_files)}] {filename} ({filesize_mb:.1f} MB)...")

        # Sample large files
        sample_rate = 1
        if filesize > 500 * 1024 * 1024:
            sample_rate = 10
        elif filesize > 100 * 1024 * 1024:
            sample_rate = 5

        line_count = 0
        with open(filepath, 'r') as f:
            for line in f:
                line_count += 1
                total_lines += 1

                if sample_rate > 1 and line_count % sample_rate != 0:
                    continue

                result = parse_line(line)
                if not result:
                    continue

                event_type, x64_addr, hot, tick, age = result

                # Event counts
                event_counts[event_type] += sample_rate

                # Per-address tracking
                if x64_addr not in addresses:
                    addresses[x64_addr] = BlockHistory(x64_addr=x64_addr)

                history = addresses[x64_addr]

                # Count events per address
                if event_type == 'SUCCESS':
                    history.success_count += sample_rate
                    if age < history.min_age_at_success:
                        history.min_age_at_success = age
                elif event_type == 'SKIP':
                    history.skip_count += sample_rate
                else:
                    history.blocked_count += sample_rate

                # Track ages (for any event type)
                history.ages.append(age)

                # Track hot
                if hot > history.max_hot:
                    history.max_hot = hot

                # Detect recreation: if we see non-SUCCESS event after SUCCESS
                if history.last_was_success and event_type != 'SUCCESS':
                    history.recreations += 1

                history.last_was_success = (event_type == 'SUCCESS')

                if line_count % 2000000 == 0:
                    print(f"    {line_count // 1000000}M lines...")

    print(f"\nProcessed {total_lines:,} lines, {len(addresses):,} unique addresses\n")

    # ========== CATEGORIZE ADDRESSES ==========

    # Category 1: Ever BLOCKED (had at least one BLOCKED event)
    ever_blocked = [a for a in addresses.values() if a.blocked_count > 0]

    # Category 2: ONLY BLOCKED (never had SUCCESS or SKIP)
    only_blocked = [a for a in addresses.values()
                    if a.blocked_count > 0 and a.success_count == 0 and a.skip_count == 0]

    # Category 3: Ever PURGED (had at least one SUCCESS)
    ever_purged = [a for a in addresses.values() if a.success_count > 0]

    # Category 4: Never PURGED but could have been (had SKIP but no SUCCESS)
    never_purged_skip = [a for a in addresses.values()
                         if a.success_count == 0 and a.skip_count > 0]

    # Category 5: Had both BLOCKED and SUCCESS (was blocked but eventually purged)
    blocked_then_purged = [a for a in addresses.values()
                           if a.blocked_count > 0 and a.success_count > 0]

    # ========== REPORT ==========

    print("=" * 80)
    print("         ADDRESS-BASED ANALYSIS")
    print("=" * 80)

    total_addrs = len(addresses)

    print("\n1. ADDRESS CATEGORY BREAKDOWN")
    print("-" * 80)
    print(f"{'Category':<55} {'Count':>12} {'% of Total':>12}")
    print("-" * 80)
    print(f"{'Total unique x64 addresses':<55} {total_addrs:>12,} {'100.0%':>12}")
    print()
    print(f"{'A. Ever BLOCKED (had in_used > 0 at some point)':<55} {len(ever_blocked):>12,} {len(ever_blocked)/total_addrs*100:>11.1f}%")
    print(f"{'   └─ ONLY BLOCKED (never purgeable)':<55} {len(only_blocked):>12,} {len(only_blocked)/total_addrs*100:>11.1f}%")
    print(f"{'   └─ Blocked but eventually PURGED':<55} {len(blocked_then_purged):>12,} {len(blocked_then_purged)/total_addrs*100:>11.1f}%")
    print()
    print(f"{'B. Ever PURGED (had SUCCESS)':<55} {len(ever_purged):>12,} {len(ever_purged)/total_addrs*100:>11.1f}%")
    print(f"{'C. Never PURGED (only SKIP, too young)':<55} {len(never_purged_skip):>12,} {len(never_purged_skip)/total_addrs*100:>11.1f}%")
    print("-" * 80)

    # Event counts for comparison
    total_events = sum(event_counts.values())
    print("\n2. EVENT-BASED COMPARISON (for reference)")
    print("-" * 80)
    print(f"{'Event Type':<20} {'Count':>15} {'Percentage':>15}")
    print("-" * 80)
    for evt in ['SUCCESS', 'SKIP', 'BLOCKED']:
        count = event_counts[evt]
        pct = count / total_events * 100 if total_events > 0 else 0
        print(f"{evt:<20} {count:>15,} {pct:>14.1f}%")
    print("-" * 80)
    print(f"{'TOTAL':<20} {total_events:>15,} {'100.0%':>15}")

    print("\n" + "=" * 80)
    print("3. AGE DISTRIBUTION FOR PURGEABLE ADDRESSES")
    print("=" * 80)

    # Collect ages from addresses that were ever purgeable (not ONLY_BLOCKED)
    purgeable_addrs = [a for a in addresses.values() if a.success_count > 0 or a.skip_count > 0]

    # For threshold analysis, use minimum age at SUCCESS or ages from SKIP-only
    threshold_relevant_ages = []
    for addr in purgeable_addrs:
        if addr.success_count > 0:
            # Use the minimum age when this address was successfully purged
            threshold_relevant_ages.append(addr.min_age_at_success)
        else:
            # Never purged - use the maximum age observed (closest to being purgeable)
            if addr.ages:
                threshold_relevant_ages.append(max(addr.ages))

    if not threshold_relevant_ages:
        print("No purgeable age data!")
        return

    sorted_ages = sorted(threshold_relevant_ages)
    n = len(sorted_ages)

    print(f"\nPurgeable addresses: {len(purgeable_addrs):,}")
    print(f"Current threshold: 256")
    print(f"Mean age (at purge or max observed): {statistics.mean(threshold_relevant_ages):,.1f}")
    print(f"Median age: {statistics.median(threshold_relevant_ages):,.0f}")
    print(f"Min age: {min(threshold_relevant_ages):,}")
    print(f"Max age: {max(threshold_relevant_ages):,}")

    # Percentiles
    print("\nAge Percentiles (for threshold selection):")
    percentiles = [10, 25, 50, 75, 90, 95, 99]
    for p in percentiles:
        idx = int(n * p / 100)
        age_at_p = sorted_ages[min(idx, n-1)]
        print(f"  P{p:2d}: age = {age_at_p:,}")

    # CDF at various thresholds (address-based)
    print("\nCDF: At threshold X, what % of purgeable addresses could be purged?")
    thresholds = [64, 128, 256, 512, 1024, 2048, 4096]
    for thresh in thresholds:
        purgeable = sum(1 for a in threshold_relevant_ages if a >= thresh)
        pct = purgeable / n * 100
        print(f"  threshold={thresh:5d}: {pct:5.1f}% of addresses purgeable ({purgeable:,} addresses)")

    print("\n" + "=" * 80)
    print("4. RECREATION ANALYSIS (address-based)")
    print("=" * 80)

    # Addresses that were purged then recreated
    recreated_addrs = [a for a in addresses.values() if a.recreations > 0]

    print(f"\nAddresses ever purged: {len(ever_purged):,}")
    print(f"Addresses recreated after purge: {len(recreated_addrs):,}")

    if ever_purged:
        recreation_rate = len(recreated_addrs) / len(ever_purged) * 100
        print(f"Recreation rate: {recreation_rate:.1f}% of purged addresses were recreated")

        if recreation_rate > 50:
            print("  WARNING: High recreation rate suggests threshold is too aggressive")
            print("  Blocks are being purged prematurely and need to be recompiled")
        elif recreation_rate > 20:
            print("  MODERATE: Some recreation, may benefit from higher threshold")
        else:
            print("  GOOD: Low recreation rate, threshold seems appropriate")

    # Multi-purge addresses
    multi_purge = [a for a in ever_purged if a.success_count > 1]
    if multi_purge:
        print(f"\nAddresses purged multiple times: {len(multi_purge):,}")
        # Note: success_count includes sampling multiplier, so divide by average sample rate
        total_success = sum(a.success_count for a in multi_purge)
        avg_purges = total_success / len(multi_purge)
        print(f"  Avg purge count per address: {avg_purges:.1f}")

    print("\n" + "=" * 80)
    print("5. THRESHOLD SENSITIVITY (address-based)")
    print("=" * 80)

    print("\nSimulating different thresholds on purgeable addresses:")
    print("(Based on minimum age at SUCCESS or max observed age)")
    print()
    print(f"{'Threshold':<12} {'Would Purge':>18} {'Would Not Purge':>18} {'Purge Rate':>12}")
    print("-" * 62)

    for thresh in [64, 128, 256, 512, 1024, 2048, 4096, 8192]:
        would_purge = sum(1 for a in threshold_relevant_ages if a >= thresh)
        would_not = n - would_purge
        rate = would_purge / n * 100 if n > 0 else 0
        print(f"{thresh:<12} {would_purge:>18,} {would_not:>18,} {rate:>11.1f}%")

    print("\n" + "=" * 80)
    print("6. BLOCKED ADDRESS ANALYSIS")
    print("=" * 80)

    print(f"\nTotal addresses with BLOCKED events: {len(ever_blocked):,} ({len(ever_blocked)/total_addrs*100:.1f}%)")
    print(f"  - ONLY BLOCKED (never became purgeable): {len(only_blocked):,} ({len(only_blocked)/total_addrs*100:.1f}%)")
    print(f"  - Eventually became purgeable: {len(blocked_then_purged):,} ({len(blocked_then_purged)/total_addrs*100:.1f}%)")

    if only_blocked:
        only_blocked_hot = [a.max_hot for a in only_blocked]
        print(f"\nONLY_BLOCKED addresses (always in_used):")
        print(f"  Mean max_hot: {statistics.mean(only_blocked_hot):,.1f}")
        print(f"  Median max_hot: {statistics.median(only_blocked_hot):,.0f}")
        print(f"  These are likely core/active code blocks that should never be purged")

    print("\n" + "=" * 80)
    print("7. DYNAMIC THRESHOLD DESIGN RECOMMENDATIONS")
    print("=" * 80)

    median_age = statistics.median(threshold_relevant_ages)
    p90_age = sorted_ages[int(n * 0.90)]
    p75_age = sorted_ages[int(n * 0.75)]

    print("\nBased on ADDRESS-BASED analysis:")
    print()
    print(f"1. CURRENT STATE (threshold=256):")
    print(f"   - {len(ever_purged)/total_addrs*100:.1f}% of addresses ever purged")
    print(f"   - {len(only_blocked)/total_addrs*100:.1f}% always blocked (hot code, never purgeable)")
    if ever_purged:
        print(f"   - {len(recreated_addrs)/len(ever_purged)*100:.1f}% recreation rate (too high if >30%)")
    print()
    print(f"2. FEEDBACK SIGNALS for dynamic threshold:")
    print(f"   - Recreation rate: Target < 30%")
    print(f"   - SKIP/(SKIP+SUCCESS) ratio in events: Target 30-70%")
    print(f"   - Memory pressure: Lower threshold when memory is constrained")
    print()
    print(f"3. SUGGESTED THRESHOLD RANGE:")
    print(f"   - Minimum: {int(median_age * 0.25):,} (aggressive purging)")
    print(f"   - Default: {int(p75_age):,} (75th percentile - conservative)")
    print(f"   - Maximum: {int(p90_age * 1.5):,} (very conservative)")
    print()
    print(f"4. ADAPTIVE ALGORITHM:")
    print(f"   threshold_min = {int(median_age * 0.25):,}")
    print(f"   threshold_max = {int(p90_age * 1.5):,}")
    print(f"   threshold_default = {int(p75_age):,}")
    print()
    print(f"   Every N purge cycles:")
    print(f"     skip_ratio = skip_events / (skip_events + success_events)")
    print(f"     if skip_ratio > 0.80:")
    print(f"       threshold = min(threshold * 1.5, threshold_max)")
    print(f"     elif skip_ratio < 0.30:")
    print(f"       threshold = max(threshold * 0.75, threshold_min)")
    print()

    # Export data
    csv_path = os.path.join(directory, "threshold_analysis_address_based.csv")
    print(f"Exporting address data to: {csv_path}")

    with open(csv_path, 'w') as f:
        f.write("x64_addr,success_count,skip_count,blocked_count,min_age_success,max_hot,recreations,category\n")
        for addr in addresses.values():
            if addr.success_count > 0 and addr.blocked_count > 0:
                cat = "BLOCKED_THEN_PURGED"
            elif addr.success_count > 0:
                cat = "PURGED"
            elif addr.blocked_count > 0 and addr.skip_count == 0:
                cat = "ONLY_BLOCKED"
            elif addr.skip_count > 0:
                cat = "NEVER_PURGED_SKIP"
            else:
                cat = "OTHER"

            min_age = addr.min_age_at_success if addr.success_count > 0 else -1
            f.write(f"0x{addr.x64_addr:x},{addr.success_count},{addr.skip_count},{addr.blocked_count},{min_age},{addr.max_hot},{addr.recreations},{cat}\n")

    print("Done!")


if __name__ == '__main__':
    directory = sys.argv[1] if len(sys.argv) > 1 else "/Users/devaraja/Downloads/Box64 tick hot"
    analyze_for_dynamic_threshold(directory)
