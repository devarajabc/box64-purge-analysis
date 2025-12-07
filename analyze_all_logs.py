#!/usr/bin/env python3
"""
Box64 Dynarec Block Analysis - ADDRESS-BASED, PER-PID

Analyzes relationships between tick, hot, purgeable, and recreation
for each unique x64 address, separated by PID.

Key Questions:
1. tick vs hot: Are recently-used blocks also frequently-used?
2. hot vs purgeable: Do hot blocks become purgeable or stay blocked?
3. hot vs recreation: Are high-hot blocks recreated after purging?
4. age vs recreation: At what age do purged blocks get recreated?

Address Categories:
- ONLY_BLOCKED: Always in_used, never purgeable (core hot code)
- PURGED_RECREATED: Purged and came back (threshold too aggressive)
- PURGED_GONE: Purged and never seen again (good purge decisions)
- NEVER_PURGED: Had SKIP events but never purged (threshold too high?)
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
class PurgeEvent:
    """Represents a single purge SUCCESS event."""
    x64_addr: int
    tick: int        # last_used_tick
    age: int         # current_age at purge time
    hot: int         # hot value at purge time
    recreated: bool = False  # Was this address seen again after this purge?


@dataclass
class AddressStats:
    """Complete statistics for a single x64 address."""
    x64_addr: int

    # Event counts
    success_count: int = 0
    skip_count: int = 0
    blocked_count: int = 0

    # Hot tracking
    max_hot: int = 0
    min_hot: int = 999999999
    last_hot: int = 0

    # Tick/Age tracking
    first_tick: int = 999999999
    last_tick: int = 0
    min_age_at_success: int = 999999999

    # Recreation tracking
    recreation_count: int = 0
    last_event_was_success: bool = False

    # Category (computed later)
    category: str = ""


@dataclass
class PIDStats:
    """Statistics for a single PID."""
    pid: str
    filename: str
    filesize_mb: float
    addresses: Dict[int, AddressStats] = field(default_factory=dict)
    total_events: Dict[str, int] = field(default_factory=lambda: {'SUCCESS': 0, 'SKIP': 0, 'BLOCKED': 0})
    purge_events: List[PurgeEvent] = field(default_factory=list)  # All SUCCESS events
    line_count: int = 0


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


def extract_pid(filename: str) -> str:
    """Extract PID from filename like box64_purge_199109.log"""
    match = re.search(r'box64_purge_(\d+)', filename)
    if match:
        return match.group(1)
    # Handle files like box64_purge_199041-003.log
    match = re.search(r'box64_purge_(\d+-\d+)', filename)
    if match:
        return match.group(1)
    return os.path.basename(filename)


def get_hot_bucket(hot: int) -> str:
    """Categorize hot value into bucket (10 buckets)."""
    if hot == 0:
        return '0'
    elif hot <= 10:
        return '1-10'
    elif hot <= 50:
        return '11-50'
    elif hot <= 100:
        return '51-100'
    elif hot <= 500:
        return '101-500'
    elif hot <= 1000:
        return '501-1K'
    elif hot <= 5000:
        return '1K-5K'
    elif hot <= 10000:
        return '5K-10K'
    elif hot <= 100000:
        return '10K-100K'
    else:
        return '100K+'


HOT_BUCKETS = ['0', '1-10', '11-50', '51-100', '101-500', '501-1K', '1K-5K', '5K-10K', '10K-100K', '100K+']

# 35 tick buckets for tick-based analysis (more granular)
# Tick = last_used_tick (when block was last executed)
TICK_BUCKETS = [
    '0-5K', '5K-10K', '10K-15K', '15K-20K', '20K-25K',
    '25K-30K', '30K-40K', '40K-50K', '50K-60K', '60K-70K',
    '70K-80K', '80K-90K', '90K-100K', '100K-120K', '120K-140K',
    '140K-160K', '160K-180K', '180K-200K', '200K-250K', '250K-300K',
    '300K-350K', '350K-400K', '400K-450K', '450K-500K', '500K-600K',
    '600K-700K', '700K-800K', '800K-900K', '900K-1M', '1M-1.2M',
    '1.2M-1.4M', '1.4M-1.6M', '1.6M-1.8M', '1.8M-2M', '2M+'
]


def get_tick_bucket(tick: int) -> str:
    """Categorize tick value into bucket (35 buckets)."""
    if tick < 5000:
        return '0-5K'
    elif tick < 10000:
        return '5K-10K'
    elif tick < 15000:
        return '10K-15K'
    elif tick < 20000:
        return '15K-20K'
    elif tick < 25000:
        return '20K-25K'
    elif tick < 30000:
        return '25K-30K'
    elif tick < 40000:
        return '30K-40K'
    elif tick < 50000:
        return '40K-50K'
    elif tick < 60000:
        return '50K-60K'
    elif tick < 70000:
        return '60K-70K'
    elif tick < 80000:
        return '70K-80K'
    elif tick < 90000:
        return '80K-90K'
    elif tick < 100000:
        return '90K-100K'
    elif tick < 120000:
        return '100K-120K'
    elif tick < 140000:
        return '120K-140K'
    elif tick < 160000:
        return '140K-160K'
    elif tick < 180000:
        return '160K-180K'
    elif tick < 200000:
        return '180K-200K'
    elif tick < 250000:
        return '200K-250K'
    elif tick < 300000:
        return '250K-300K'
    elif tick < 350000:
        return '300K-350K'
    elif tick < 400000:
        return '350K-400K'
    elif tick < 450000:
        return '400K-450K'
    elif tick < 500000:
        return '450K-500K'
    elif tick < 600000:
        return '500K-600K'
    elif tick < 700000:
        return '600K-700K'
    elif tick < 800000:
        return '700K-800K'
    elif tick < 900000:
        return '800K-900K'
    elif tick < 1000000:
        return '900K-1M'
    elif tick < 1200000:
        return '1M-1.2M'
    elif tick < 1400000:
        return '1.2M-1.4M'
    elif tick < 1600000:
        return '1.4M-1.6M'
    elif tick < 1800000:
        return '1.6M-1.8M'
    elif tick < 2000000:
        return '1.8M-2M'
    else:
        return '2M+'


# 35 age buckets for age-based analysis (more granular)
# Age = current_tick - last_used_tick (how long since block was last executed)
AGE_BUCKETS = [
    '256-400', '400-600', '600-800', '800-900', '900-1K',
    '1K-1.05K', '1.05K-1.1K', '1.1K-1.15K', '1.15K-1.2K', '1.2K-1.25K',
    '1.25K-1.3K', '1.3K-1.4K', '1.4K-1.5K', '1.5K-1.6K', '1.6K-1.7K',
    '1.7K-1.8K', '1.8K-1.9K', '1.9K-2K', '2K-2.2K', '2.2K-2.5K',
    '2.5K-3K', '3K-3.5K', '3.5K-4K', '4K-5K', '5K-6K',
    '6K-8K', '8K-10K', '10K-15K', '15K-20K', '20K-30K',
    '30K-50K', '50K-100K', '100K-250K', '250K-500K', '500K+'
]


def get_age_bucket(age: int) -> str:
    """Categorize age value into bucket (35 buckets)."""
    if age < 400:
        return '256-400'
    elif age < 600:
        return '400-600'
    elif age < 800:
        return '600-800'
    elif age < 900:
        return '800-900'
    elif age < 1000:
        return '900-1K'
    elif age < 1050:
        return '1K-1.05K'
    elif age < 1100:
        return '1.05K-1.1K'
    elif age < 1150:
        return '1.1K-1.15K'
    elif age < 1200:
        return '1.15K-1.2K'
    elif age < 1250:
        return '1.2K-1.25K'
    elif age < 1300:
        return '1.25K-1.3K'
    elif age < 1400:
        return '1.3K-1.4K'
    elif age < 1500:
        return '1.4K-1.5K'
    elif age < 1600:
        return '1.5K-1.6K'
    elif age < 1700:
        return '1.6K-1.7K'
    elif age < 1800:
        return '1.7K-1.8K'
    elif age < 1900:
        return '1.8K-1.9K'
    elif age < 2000:
        return '1.9K-2K'
    elif age < 2200:
        return '2K-2.2K'
    elif age < 2500:
        return '2.2K-2.5K'
    elif age < 3000:
        return '2.5K-3K'
    elif age < 3500:
        return '3K-3.5K'
    elif age < 4000:
        return '3.5K-4K'
    elif age < 5000:
        return '4K-5K'
    elif age < 6000:
        return '5K-6K'
    elif age < 8000:
        return '6K-8K'
    elif age < 10000:
        return '8K-10K'
    elif age < 15000:
        return '10K-15K'
    elif age < 20000:
        return '15K-20K'
    elif age < 30000:
        return '20K-30K'
    elif age < 50000:
        return '30K-50K'
    elif age < 100000:
        return '50K-100K'
    elif age < 250000:
        return '100K-250K'
    elif age < 500000:
        return '250K-500K'
    else:
        return '500K+'


def categorize_addresses(addresses: Dict[int, AddressStats]) -> Dict[str, List[AddressStats]]:
    """Categorize addresses and return grouped dict."""
    for stats in addresses.values():
        if stats.blocked_count > 0 and stats.success_count == 0 and stats.skip_count == 0:
            stats.category = "ONLY_BLOCKED"
        elif stats.success_count > 0 and stats.recreation_count > 0:
            stats.category = "PURGED_RECREATED"
        elif stats.success_count > 0 and stats.recreation_count == 0:
            stats.category = "PURGED_GONE"
        elif stats.skip_count > 0 and stats.success_count == 0:
            stats.category = "NEVER_PURGED"
        else:
            stats.category = "OTHER"

    categories = defaultdict(list)
    for stats in addresses.values():
        categories[stats.category].append(stats)
    return categories


def print_pid_summary(pid_stats: PIDStats):
    """Print summary for a single PID."""
    categories = categorize_addresses(pid_stats.addresses)
    total_addrs = len(pid_stats.addresses)
    total_events = sum(pid_stats.total_events.values())

    if total_addrs == 0:
        return

    # Category counts
    only_blocked = len(categories["ONLY_BLOCKED"])
    purged_recreated = len(categories["PURGED_RECREATED"])
    purged_gone = len(categories["PURGED_GONE"])
    never_purged = len(categories["NEVER_PURGED"])

    # Recreation rate
    purged_total = purged_recreated + purged_gone
    rec_rate = purged_recreated / purged_total * 100 if purged_total > 0 else 0

    # Hot stats for recreated vs gone
    recreated_hot = [s.max_hot for s in categories["PURGED_RECREATED"]] if categories["PURGED_RECREATED"] else [0]
    gone_hot = [s.max_hot for s in categories["PURGED_GONE"]] if categories["PURGED_GONE"] else [0]

    print(f"  PID {pid_stats.pid}:")
    print(f"    File: {pid_stats.filename} ({pid_stats.filesize_mb:.1f} MB)")
    print(f"    Events: {total_events:,} | Addresses: {total_addrs:,}")
    print(f"    Categories: BLOCKED={only_blocked} RECREATED={purged_recreated} GONE={purged_gone} NEVER={never_purged}")
    print(f"    Recreation rate: {rec_rate:.1f}%")
    print(f"    Avg hot: RECREATED={statistics.mean(recreated_hot):.0f} vs GONE={statistics.mean(gone_hot):.0f}")
    print()


def print_pid_hot_fate_table(pid_stats: PIDStats):
    """Print detailed hot distribution by address fate table for a single PID."""
    categories = categorize_addresses(pid_stats.addresses)
    total_addrs = len(pid_stats.addresses)
    total_events = sum(pid_stats.total_events.values())

    if total_addrs == 0:
        return

    print()
    print(f"PID {pid_stats.pid} ({total_addrs:,} addresses, {total_events/1e6:.1f}M events):")
    print("-" * 95)
    print(f"{'Hot Bucket':<12} {'Total':>8} {'BLOCKED%':>10} {'RECREATED%':>12} {'GONE%':>10} {'NEVER%':>10} {'Rec.Rate':>10}")
    print("-" * 95)

    # Calculate per-bucket statistics
    bucket_totals = defaultdict(lambda: {'blocked': 0, 'recreated': 0, 'gone': 0, 'never': 0, 'total': 0})

    for stats in pid_stats.addresses.values():
        bucket = get_hot_bucket(stats.max_hot)
        bucket_totals[bucket]['total'] += 1

        if stats.category == "ONLY_BLOCKED":
            bucket_totals[bucket]['blocked'] += 1
        elif stats.category == "PURGED_RECREATED":
            bucket_totals[bucket]['recreated'] += 1
        elif stats.category == "PURGED_GONE":
            bucket_totals[bucket]['gone'] += 1
        elif stats.category == "NEVER_PURGED":
            bucket_totals[bucket]['never'] += 1

    # Print each bucket
    grand_total = {'blocked': 0, 'recreated': 0, 'gone': 0, 'never': 0, 'total': 0}

    for bucket in HOT_BUCKETS:
        data = bucket_totals[bucket]
        total = data['total']

        if total == 0:
            print(f"{bucket:<12} {0:>8} {'-':>10} {'-':>12} {'-':>10} {'-':>10} {'-':>10}")
            continue

        blocked_pct = data['blocked'] / total * 100
        recreated_pct = data['recreated'] / total * 100
        gone_pct = data['gone'] / total * 100
        never_pct = data['never'] / total * 100

        # Recreation rate = recreated / (recreated + gone)
        purged_total = data['recreated'] + data['gone']
        rec_rate = data['recreated'] / purged_total * 100 if purged_total > 0 else 0

        print(f"{bucket:<12} {total:>8,} {blocked_pct:>9.1f}% {recreated_pct:>11.1f}% {gone_pct:>9.1f}% {never_pct:>9.1f}% {rec_rate:>9.1f}%")

        # Accumulate for grand total
        for key in grand_total:
            grand_total[key] += data[key]

    # Print total row
    print("-" * 95)
    total = grand_total['total']
    if total > 0:
        blocked_pct = grand_total['blocked'] / total * 100
        recreated_pct = grand_total['recreated'] / total * 100
        gone_pct = grand_total['gone'] / total * 100
        never_pct = grand_total['never'] / total * 100
        purged_total = grand_total['recreated'] + grand_total['gone']
        rec_rate = grand_total['recreated'] / purged_total * 100 if purged_total > 0 else 0

        print(f"{'TOTAL':<12} {total:>8,} {blocked_pct:>9.1f}% {recreated_pct:>11.1f}% {gone_pct:>9.1f}% {never_pct:>9.1f}% {rec_rate:>9.1f}%")
    print()


def analyze_all_logs(directory: str):
    """Main analysis function - ADDRESS-BASED, PER-PID."""

    print("=" * 90)
    print("    BOX64 DYNAREC BLOCK ANALYSIS - ADDRESS-BASED, PER-PID")
    print("=" * 90)
    print(f"\nScanning directory: {directory}\n")

    # Find all log files
    log_files = glob.glob(os.path.join(directory, "box64_purge_*.log"))
    log_files = sorted(log_files, key=lambda x: os.path.getsize(x))

    if not log_files:
        print("No log files found!")
        return

    print(f"Found {len(log_files)} log files\n")

    # Per-PID tracking
    pid_data: Dict[str, PIDStats] = {}

    # Global aggregated tracking
    global_addresses: Dict[int, AddressStats] = {}
    global_events = {'SUCCESS': 0, 'SKIP': 0, 'BLOCKED': 0}

    # Process files
    total_lines = 0
    for file_idx, filepath in enumerate(log_files, 1):
        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)
        filesize_mb = filesize / (1024 * 1024)
        pid = extract_pid(filename)

        print(f"[{file_idx}/{len(log_files)}] Processing {filename} (PID={pid}, {filesize_mb:.1f} MB)...")

        # Initialize PID stats
        if pid not in pid_data:
            pid_data[pid] = PIDStats(pid=pid, filename=filename, filesize_mb=filesize_mb)
        else:
            # Multiple files for same PID, accumulate size
            pid_data[pid].filesize_mb += filesize_mb

        pid_stats = pid_data[pid]

        # Sample large files
        sample_rate = 1
        if filesize > 500 * 1024 * 1024:
            sample_rate = 10
            print(f"  (Large file - sampling every {sample_rate}th line)")
        elif filesize > 100 * 1024 * 1024:
            sample_rate = 5
            print(f"  (Large file - sampling every {sample_rate}th line)")

        line_count = 0
        file_events = 0

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
                file_events += 1

                # Update PID-specific stats
                pid_stats.total_events[event_type] += sample_rate

                if x64_addr not in pid_stats.addresses:
                    pid_stats.addresses[x64_addr] = AddressStats(x64_addr=x64_addr)

                stats = pid_stats.addresses[x64_addr]
                update_address_stats(stats, event_type, hot, tick, age, sample_rate)

                # Collect purge events for event-based analysis
                if event_type == 'SUCCESS':
                    # Add purge event (will mark recreation later)
                    pid_stats.purge_events.append(PurgeEvent(
                        x64_addr=x64_addr,
                        tick=tick,
                        age=age,
                        hot=hot,
                        recreated=False
                    ))

                # Update global stats
                global_events[event_type] += sample_rate

                if x64_addr not in global_addresses:
                    global_addresses[x64_addr] = AddressStats(x64_addr=x64_addr)

                global_stats = global_addresses[x64_addr]
                update_address_stats(global_stats, event_type, hot, tick, age, sample_rate)

                if line_count % 2000000 == 0:
                    print(f"    {line_count // 1000000}M lines...")

        pid_stats.line_count += line_count
        print(f"    Done: {file_events:,} events from {line_count:,} lines")

    print(f"\nProcessed {total_lines:,} total lines")
    print(f"Found {len(pid_data)} unique PIDs")
    print(f"Found {len(global_addresses):,} unique x64 addresses (global)\n")

    # Mark recreation for purge events
    # For each PID, scan events and mark if address appears again after purge
    print("Marking recreation for purge events...")
    global_purge_events: List[PurgeEvent] = []

    for pid_stats in pid_data.values():
        if not pid_stats.purge_events:
            continue

        # Build set of addresses that appear after each event index
        # For efficiency, scan backwards and track "seen after" addresses
        seen_after = set()
        for i in range(len(pid_stats.purge_events) - 1, -1, -1):
            event = pid_stats.purge_events[i]
            if event.x64_addr in seen_after:
                event.recreated = True
            seen_after.add(event.x64_addr)

        # Add to global list
        global_purge_events.extend(pid_stats.purge_events)

    total_purge_events = len(global_purge_events)
    recreated_events = sum(1 for e in global_purge_events if e.recreated)
    print(f"Total purge events: {total_purge_events:,}")
    print(f"Recreated events: {recreated_events:,} ({recreated_events/total_purge_events*100:.1f}%)\n")

    # ========== PER-PID DETAILED TABLES ==========

    print("=" * 90)
    print("1. PER-PID DETAILED TABLES: HOT DISTRIBUTION BY ADDRESS FATE")
    print("=" * 90)

    # Sort PIDs by total events
    sorted_pids = sorted(pid_data.values(), key=lambda p: sum(p.total_events.values()), reverse=True)

    for pid_stats in sorted_pids:
        if len(pid_stats.addresses) == 0:
            continue

        print_pid_hot_fate_table(pid_stats)

    # ========== PER-PID COMPARISON TABLE ==========

    print("=" * 90)
    print("2. PER-PID COMPARISON TABLE")
    print("=" * 90)
    print()

    print(f"{'PID':<12} {'Events':>12} {'Addrs':>10} {'BLOCKED%':>10} {'RECREATED%':>12} {'GONE%':>10} {'Rec.Rate':>10}")
    print("-" * 90)

    for pid_stats in sorted_pids:
        if len(pid_stats.addresses) == 0:
            continue

        categories = categorize_addresses(pid_stats.addresses)
        total_addrs = len(pid_stats.addresses)
        total_ev = sum(pid_stats.total_events.values())

        only_blocked_pct = len(categories["ONLY_BLOCKED"]) / total_addrs * 100
        purged_recreated = len(categories["PURGED_RECREATED"])
        purged_gone = len(categories["PURGED_GONE"])
        purged_total = purged_recreated + purged_gone

        recreated_pct = purged_recreated / total_addrs * 100
        gone_pct = purged_gone / total_addrs * 100
        rec_rate = purged_recreated / purged_total * 100 if purged_total > 0 else 0

        print(f"{pid_stats.pid:<12} {total_ev:>12,} {total_addrs:>10,} {only_blocked_pct:>9.1f}% {recreated_pct:>11.1f}% {gone_pct:>9.1f}% {rec_rate:>9.1f}%")

    print("-" * 90)

    # ========== PER-PID HOT vs RECREATION ==========

    print("\n" + "=" * 90)
    print("3. PER-PID: HOT vs RECREATION ANALYSIS")
    print("=" * 90)
    print()

    print(f"{'PID':<12} {'Purged':>10} {'Recreated':>10} {'Rec.Rate':>10} {'Recreated AvgHot':>18} {'Gone AvgHot':>15}")
    print("-" * 90)

    for pid_stats in sorted_pids:
        if len(pid_stats.addresses) == 0:
            continue

        categories = categorize_addresses(pid_stats.addresses)
        purged_recreated = categories["PURGED_RECREATED"]
        purged_gone = categories["PURGED_GONE"]
        purged_total = len(purged_recreated) + len(purged_gone)

        if purged_total == 0:
            continue

        rec_rate = len(purged_recreated) / purged_total * 100

        recreated_hot = statistics.mean([s.max_hot for s in purged_recreated]) if purged_recreated else 0
        gone_hot = statistics.mean([s.max_hot for s in purged_gone]) if purged_gone else 0

        print(f"{pid_stats.pid:<12} {purged_total:>10,} {len(purged_recreated):>10,} {rec_rate:>9.1f}% {recreated_hot:>18,.0f} {gone_hot:>15,.0f}")

    print("-" * 90)

    # ========== PER-PID RECREATION BY HOT BUCKET ==========

    print("\n" + "=" * 90)
    print("4. PER-PID: RECREATION RATE BY HOT BUCKET")
    print("=" * 90)
    print()

    # Header
    print(f"{'PID':<12}", end="")
    for bucket in HOT_BUCKETS:
        print(f" {bucket:>10}", end="")
    print()
    print("-" * 95)

    for pid_stats in sorted_pids:
        if len(pid_stats.addresses) == 0:
            continue

        categories = categorize_addresses(pid_stats.addresses)
        purged_addrs = categories["PURGED_RECREATED"] + categories["PURGED_GONE"]
        recreated_addrs = categories["PURGED_RECREATED"]

        if len(purged_addrs) < 100:  # Skip PIDs with too few purged addresses
            continue

        print(f"{pid_stats.pid:<12}", end="")

        for bucket in HOT_BUCKETS:
            purged_in_bucket = [s for s in purged_addrs if get_hot_bucket(s.max_hot) == bucket]
            recreated_in_bucket = [s for s in recreated_addrs if get_hot_bucket(s.max_hot) == bucket]
            rate = len(recreated_in_bucket) / len(purged_in_bucket) * 100 if purged_in_bucket else 0
            print(f" {rate:>9.1f}%", end="")
        print()

    print("-" * 95)

    # ========== GLOBAL AGGREGATED ANALYSIS ==========

    print("\n" + "=" * 90)
    print("5. GLOBAL AGGREGATED ANALYSIS (all PIDs combined)")
    print("=" * 90)

    global_categories = categorize_addresses(global_addresses)
    total_addrs = len(global_addresses)

    print(f"\nTotal unique x64 addresses: {total_addrs:,}")
    print()

    cat_order = ["ONLY_BLOCKED", "PURGED_RECREATED", "PURGED_GONE", "NEVER_PURGED", "OTHER"]
    cat_descriptions = {
        "ONLY_BLOCKED": "Always in_used (core code)",
        "PURGED_RECREATED": "Purged then came back",
        "PURGED_GONE": "Purged, never returned",
        "NEVER_PURGED": "Always too young (SKIP)",
        "OTHER": "Mixed/edge cases"
    }

    print(f"{'Category':<25} {'Count':>12} {'% of Total':>12} {'Description':<30}")
    print("-" * 80)

    for cat in cat_order:
        count = len(global_categories[cat])
        pct = count / total_addrs * 100 if total_addrs > 0 else 0
        desc = cat_descriptions.get(cat, "")
        print(f"{cat:<25} {count:>12,} {pct:>11.1f}% {desc:<30}")

    print("-" * 80)
    print(f"{'TOTAL':<25} {total_addrs:>12,} {'100.0%':>12}")

    # ========== GLOBAL RECREATION BY HOT BUCKET ==========

    print("\n" + "=" * 90)
    print("6. GLOBAL: RECREATION RATE BY HOT BUCKET")
    print("=" * 90)

    purged_addrs = global_categories["PURGED_RECREATED"] + global_categories["PURGED_GONE"]
    recreated_addrs = global_categories["PURGED_RECREATED"]

    print(f"\nTotal purged addresses: {len(purged_addrs):,}")
    print(f"Addresses recreated after purge: {len(recreated_addrs):,}")

    if purged_addrs:
        recreation_rate = len(recreated_addrs) / len(purged_addrs) * 100
        print(f"Overall recreation rate: {recreation_rate:.1f}%")

    print(f"\n{'Hot Bucket':<15} {'Purged':>12} {'Recreated':>12} {'Rec. Rate':>12} {'Conclusion':<25}")
    print("-" * 80)

    for bucket in HOT_BUCKETS:
        purged_in_bucket = [s for s in purged_addrs if get_hot_bucket(s.max_hot) == bucket]
        recreated_in_bucket = [s for s in recreated_addrs if get_hot_bucket(s.max_hot) == bucket]

        rate = len(recreated_in_bucket) / len(purged_in_bucket) * 100 if purged_in_bucket else 0

        if rate > 70:
            conclusion = "VERY HIGH - protect!"
        elif rate > 50:
            conclusion = "HIGH - consider protect"
        elif rate > 30:
            conclusion = "MODERATE"
        else:
            conclusion = "LOW - OK to purge"

        print(f"{bucket:<15} {len(purged_in_bucket):>12,} {len(recreated_in_bucket):>12,} {rate:>11.1f}% {conclusion:<25}")

    # ========== GLOBAL HOT vs RECREATION CORRELATION ==========

    print("\n" + "=" * 90)
    print("7. GLOBAL: HOT vs RECREATION CORRELATION")
    print("=" * 90)

    if recreated_addrs:
        recreated_hots = [s.max_hot for s in recreated_addrs]
        gone_hots = [s.max_hot for s in global_categories["PURGED_GONE"]]

        print(f"\nPURGED_RECREATED addresses:")
        print(f"  Mean max_hot: {statistics.mean(recreated_hots):,.1f}")
        print(f"  Median max_hot: {statistics.median(recreated_hots):,.0f}")

        if gone_hots:
            print(f"\nPURGED_GONE addresses:")
            print(f"  Mean max_hot: {statistics.mean(gone_hots):,.1f}")
            print(f"  Median max_hot: {statistics.median(gone_hots):,.0f}")

            mean_recreated = statistics.mean(recreated_hots)
            mean_gone = statistics.mean(gone_hots)

            print(f"\nComparison:")
            if mean_recreated > mean_gone * 1.5:
                print(f"  WARNING: Recreated blocks are {mean_recreated/mean_gone:.1f}x hotter than gone blocks!")
                print(f"  This suggests we're purging valuable hot code prematurely.")
            elif mean_recreated > mean_gone:
                print(f"  NOTICE: Recreated blocks are slightly hotter ({mean_recreated/mean_gone:.1f}x)")
            else:
                print(f"  GOOD: Recreated blocks are not hotter than permanently-gone blocks.")

    # ========== TICK-BASED ANALYSIS (EVENT-BASED) ==========

    print("\n" + "=" * 90)
    print("8. TICK-BASED ANALYSIS: PURGE & RECREATION BY TICK BUCKET (EVENT-BASED)")
    print("=" * 90)
    print()
    print("Tick = last_used_tick (when block was last executed)")
    print("Each purge event counted separately (same address can appear multiple times)")
    print()

    # Group purge EVENTS by their tick value
    tick_bucket_data = defaultdict(lambda: {'purged': 0, 'recreated': 0, 'gone': 0})

    for event in global_purge_events:
        bucket = get_tick_bucket(event.tick)
        tick_bucket_data[bucket]['purged'] += 1
        if event.recreated:
            tick_bucket_data[bucket]['recreated'] += 1
        else:
            tick_bucket_data[bucket]['gone'] += 1

    total_tick_purged = sum(d['purged'] for d in tick_bucket_data.values())

    print(f"{'Tick Range':<15} {'Purged':>10} {'Purge%':>10} {'Recreated':>12} {'Gone':>10} {'Rec.Rate':>12}")
    print("-" * 80)

    cum_tick_purged = 0
    cum_tick_recreated = 0

    for bucket in TICK_BUCKETS:
        data = tick_bucket_data[bucket]
        purged = data['purged']
        recreated = data['recreated']
        gone = data['gone']

        cum_tick_purged += purged
        cum_tick_recreated += recreated

        purge_pct = purged / total_tick_purged * 100 if total_tick_purged > 0 else 0
        rec_rate = recreated / purged * 100 if purged > 0 else 0

        print(f"{bucket:<15} {purged:>10,} {purge_pct:>9.1f}% {recreated:>12,} {gone:>10,} {rec_rate:>11.1f}%")

    print("-" * 80)
    overall_tick_rec = cum_tick_recreated / cum_tick_purged * 100 if cum_tick_purged > 0 else 0
    print(f"{'TOTAL':<15} {cum_tick_purged:>10,} {'100.0%':>10} {cum_tick_recreated:>12,} {cum_tick_purged - cum_tick_recreated:>10,} {overall_tick_rec:>11.1f}%")

    # ========== AGE-BASED ANALYSIS (EVENT-BASED) ==========

    print("\n" + "=" * 90)
    print("9. AGE-BASED ANALYSIS: PURGE & RECREATION BY AGE BUCKET (EVENT-BASED)")
    print("=" * 90)
    print()
    print("Age = current_tick - last_used_tick (how long since block was last executed)")
    print("Each purge event counted separately (same address can appear multiple times)")
    print()

    # Group purge EVENTS by their age value
    age_bucket_data = defaultdict(lambda: {'purged': 0, 'recreated': 0, 'gone': 0})

    for event in global_purge_events:
        bucket = get_age_bucket(event.age)
        age_bucket_data[bucket]['purged'] += 1
        if event.recreated:
            age_bucket_data[bucket]['recreated'] += 1
        else:
            age_bucket_data[bucket]['gone'] += 1

    total_purged = sum(d['purged'] for d in age_bucket_data.values())

    print(f"{'Age Range':<15} {'Purged':>10} {'Purge%':>10} {'Recreated':>12} {'Gone':>10} {'Rec.Rate':>12}")
    print("-" * 80)

    cumulative_purged = 0
    cumulative_recreated = 0

    for bucket in AGE_BUCKETS:
        data = age_bucket_data[bucket]
        purged = data['purged']
        recreated = data['recreated']
        gone = data['gone']

        cumulative_purged += purged
        cumulative_recreated += recreated

        purge_pct = purged / total_purged * 100 if total_purged > 0 else 0
        rec_rate = recreated / purged * 100 if purged > 0 else 0

        print(f"{bucket:<15} {purged:>10,} {purge_pct:>9.1f}% {recreated:>12,} {gone:>10,} {rec_rate:>11.1f}%")

    print("-" * 80)
    overall_rec = cumulative_recreated / cumulative_purged * 100 if cumulative_purged > 0 else 0
    print(f"{'TOTAL':<15} {cumulative_purged:>10,} {'100.0%':>10} {cumulative_recreated:>12,} {cumulative_purged - cumulative_recreated:>10,} {overall_rec:>11.1f}%")

    # Save both tick and age tables to one file
    summary_path = os.path.join(directory, "tick_age_recreation_summary.txt")
    with open(summary_path, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("BOX64 DYNAREC PURGE ANALYSIS: TICK & AGE vs RECREATION RATE\n")
        f.write("(EVENT-BASED: Each purge event counted separately)\n")
        f.write("=" * 80 + "\n")
        f.write(f"\nData Source: {len(log_files)} log files, {len(global_addresses):,} unique x64 addresses\n")
        f.write(f"Threshold: 256 (fixed)\n")
        f.write(f"Total Purge Events: {total_purge_events:,}\n")
        f.write(f"Recreated Events: {recreated_events:,} ({recreated_events/total_purge_events*100:.1f}%)\n")

        # ===== TICK TABLE =====
        f.write("\n" + "=" * 80 + "\n")
        f.write("TABLE 1: TICK BUCKET ANALYSIS (35 buckets)\n")
        f.write("Tick = last_used_tick (when block was last executed)\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"+{'-'*15}+{'-'*10}+{'-'*10}+{'-'*12}+{'-'*10}+{'-'*15}+\n")
        f.write(f"| {'Tick':<13} | {'Purged':>8} | {'Purge%':>8} | {'Recreated':>10} | {'Gone':>8} | {'Rec. Rate':>13} |\n")
        f.write(f"+{'-'*15}+{'-'*10}+{'-'*10}+{'-'*12}+{'-'*10}+{'-'*15}+\n")

        for bucket in TICK_BUCKETS:
            data = tick_bucket_data[bucket]
            purged = data['purged']
            recreated = data['recreated']
            gone = data['gone']
            purge_pct = purged / total_tick_purged * 100 if total_tick_purged > 0 else 0
            rec_rate = recreated / purged * 100 if purged > 0 else 0
            f.write(f"| {bucket:<13} | {purged:>8,} | {purge_pct:>7.1f}% | {recreated:>10,} | {gone:>8,} | {rec_rate:>12.1f}% |\n")

        f.write(f"+{'-'*15}+{'-'*10}+{'-'*10}+{'-'*12}+{'-'*10}+{'-'*15}+\n")
        f.write(f"| {'TOTAL':<13} | {cum_tick_purged:>8,} | {'100.0%':>8} | {cum_tick_recreated:>10,} | {cum_tick_purged - cum_tick_recreated:>8,} | {overall_tick_rec:>12.1f}% |\n")
        f.write(f"+{'-'*15}+{'-'*10}+{'-'*10}+{'-'*12}+{'-'*10}+{'-'*15}+\n")

        # ===== AGE TABLE =====
        f.write("\n" + "=" * 80 + "\n")
        f.write("TABLE 2: AGE BUCKET ANALYSIS (35 buckets)\n")
        f.write("Age = current_tick - last_used_tick (how long since block was last executed)\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"+{'-'*15}+{'-'*10}+{'-'*10}+{'-'*12}+{'-'*10}+{'-'*15}+\n")
        f.write(f"| {'Age':<13} | {'Purged':>8} | {'Purge%':>8} | {'Recreated':>10} | {'Gone':>8} | {'Rec. Rate':>13} |\n")
        f.write(f"+{'-'*15}+{'-'*10}+{'-'*10}+{'-'*12}+{'-'*10}+{'-'*15}+\n")

        for bucket in AGE_BUCKETS:
            data = age_bucket_data[bucket]
            purged = data['purged']
            recreated = data['recreated']
            gone = data['gone']
            purge_pct = purged / total_purged * 100 if total_purged > 0 else 0
            rec_rate = recreated / purged * 100 if purged > 0 else 0
            f.write(f"| {bucket:<13} | {purged:>8,} | {purge_pct:>7.1f}% | {recreated:>10,} | {gone:>8,} | {rec_rate:>12.1f}% |\n")

        f.write(f"+{'-'*15}+{'-'*10}+{'-'*10}+{'-'*12}+{'-'*10}+{'-'*15}+\n")
        f.write(f"| {'TOTAL':<13} | {cumulative_purged:>8,} | {'100.0%':>8} | {cumulative_recreated:>10,} | {cumulative_purged - cumulative_recreated:>8,} | {overall_rec:>12.1f}% |\n")
        f.write(f"+{'-'*15}+{'-'*10}+{'-'*10}+{'-'*12}+{'-'*10}+{'-'*15}+\n")

        # ===== KEY OBSERVATIONS =====
        f.write("\n" + "=" * 80 + "\n")
        f.write("KEY OBSERVATIONS\n")
        f.write("=" * 80 + "\n\n")

        # Find tick peak
        peak_tick_bucket = max(TICK_BUCKETS, key=lambda b: tick_bucket_data[b]['purged'])
        f.write(f"1. TICK DISTRIBUTION:\n")
        f.write(f"   - Most purges at tick: {peak_tick_bucket}\n")
        f.write(f"   - Purged at that tick: {tick_bucket_data[peak_tick_bucket]['purged']:,} ({tick_bucket_data[peak_tick_bucket]['purged']/total_tick_purged*100:.1f}%)\n\n")

        # Find age peak
        peak_age_bucket = max(AGE_BUCKETS, key=lambda b: age_bucket_data[b]['purged'])
        f.write(f"2. AGE DISTRIBUTION:\n")
        f.write(f"   - Most purges at age: {peak_age_bucket}\n")
        f.write(f"   - Purged at that age: {age_bucket_data[peak_age_bucket]['purged']:,} ({age_bucket_data[peak_age_bucket]['purged']/total_purged*100:.1f}%)\n\n")

        # Find age where recreation drops below 50%
        low_rec_age = None
        for bucket in AGE_BUCKETS:
            data = age_bucket_data[bucket]
            if data['purged'] > 100:
                rate = data['recreated'] / data['purged'] * 100
                if rate < 50:
                    low_rec_age = bucket
                    break

        f.write(f"3. RECREATION vs AGE:\n")
        if low_rec_age:
            f.write(f"   - Recreation rate drops below 50% at age: {low_rec_age}\n")
            f.write(f"   - Recommendation: Set threshold >= {low_rec_age} to achieve <50% recreation\n")
        else:
            f.write(f"   - Recreation rate stays high (>50%) across all age ranges\n")
            f.write(f"   - This suggests the threshold needs to be much higher\n")

        f.write("\n" + "=" * 80 + "\n")

    print(f"\nSaved tick & age summary to: {summary_path}")

    # ========== KEY INSIGHTS ==========

    print("\n" + "=" * 90)
    print("10. KEY INSIGHTS SUMMARY")
    print("=" * 90)
    print()

    # Insight 1: PID variation
    rec_rates = []
    for pid_stats in sorted_pids:
        categories = categorize_addresses(pid_stats.addresses)
        purged_total = len(categories["PURGED_RECREATED"]) + len(categories["PURGED_GONE"])
        if purged_total > 100:
            rate = len(categories["PURGED_RECREATED"]) / purged_total * 100
            rec_rates.append((pid_stats.pid, rate))

    if rec_rates:
        rates_only = [r[1] for r in rec_rates]
        print(f"1. PID VARIATION in recreation rate:")
        print(f"   Min: {min(rates_only):.1f}% (PID {min(rec_rates, key=lambda x: x[1])[0]})")
        print(f"   Max: {max(rates_only):.1f}% (PID {max(rec_rates, key=lambda x: x[1])[0]})")
        print(f"   Avg: {statistics.mean(rates_only):.1f}%")
        if max(rates_only) - min(rates_only) > 20:
            print(f"   HIGH VARIATION - different processes have different behavior!")
        else:
            print(f"   Consistent across processes")

    # Insight 2: Global recreation rate
    if purged_addrs:
        rec_rate = len(recreated_addrs) / len(purged_addrs) * 100
        print(f"\n2. GLOBAL RECREATION RATE: {rec_rate:.1f}%")
        if rec_rate > 50:
            print(f"   HIGH - Current threshold is TOO AGGRESSIVE")
        elif rec_rate > 30:
            print(f"   MODERATE - Consider increasing threshold")
        else:
            print(f"   LOW - Threshold seems appropriate")

    # Insight 3: Hot correlation
    if recreated_addrs and global_categories["PURGED_GONE"]:
        mean_recreated = statistics.mean([s.max_hot for s in recreated_addrs])
        mean_gone = statistics.mean([s.max_hot for s in global_categories["PURGED_GONE"]])
        print(f"\n3. HOT vs RECREATION:")
        print(f"   Recreated blocks avg hot: {mean_recreated:,.0f}")
        print(f"   Gone blocks avg hot: {mean_gone:,.0f}")
        print(f"   Ratio: {mean_recreated/mean_gone:.1f}x")
        if mean_recreated > mean_gone * 1.5:
            print(f"   PROBLEM: We're purging valuable hot code!")

    print("\n" + "=" * 90)

    # ========== EXPORT CSV ==========

    csv_path = os.path.join(directory, "address_analysis_by_pid.csv")
    print(f"\nExporting to: {csv_path}")

    with open(csv_path, 'w') as f:
        f.write("pid,x64_addr,category,max_hot,success_count,skip_count,blocked_count,")
        f.write("min_age_success,recreation_count,first_tick,last_tick\n")

        for pid_stats in pid_data.values():
            for stats in pid_stats.addresses.values():
                min_age = stats.min_age_at_success if stats.min_age_at_success < 999999999 else -1
                f.write(f"{pid_stats.pid},0x{stats.x64_addr:x},{stats.category},{stats.max_hot},")
                f.write(f"{stats.success_count},{stats.skip_count},{stats.blocked_count},")
                f.write(f"{min_age},{stats.recreation_count},{stats.first_tick},{stats.last_tick}\n")

    total_exported = sum(len(p.addresses) for p in pid_data.values())
    print(f"Exported {total_exported:,} address records across {len(pid_data)} PIDs")
    print("\nDone!")


def update_address_stats(stats: AddressStats, event_type: str, hot: int, tick: int, age: int, sample_rate: int):
    """Update address statistics with a new event."""
    # Event counts
    if event_type == 'SUCCESS':
        stats.success_count += sample_rate
        if age < stats.min_age_at_success:
            stats.min_age_at_success = age
    elif event_type == 'SKIP':
        stats.skip_count += sample_rate
    else:
        stats.blocked_count += sample_rate

    # Hot tracking
    if hot > stats.max_hot:
        stats.max_hot = hot
    if hot < stats.min_hot:
        stats.min_hot = hot
    stats.last_hot = hot

    # Tick tracking
    if tick < stats.first_tick:
        stats.first_tick = tick
    if tick > stats.last_tick:
        stats.last_tick = tick

    # Recreation detection
    if stats.last_event_was_success and event_type != 'SUCCESS':
        stats.recreation_count += 1

    stats.last_event_was_success = (event_type == 'SUCCESS')


if __name__ == '__main__':
    directory = sys.argv[1] if len(sys.argv) > 1 else "/Users/devaraja/Downloads/Box64 tick hot"
    analyze_all_logs(directory)
