# Box64 Dynarec Purge Analysis

Analysis tools for Box64 dynamic recompiler block purge logs. These scripts help analyze and optimize cache eviction policies by studying the relationship between block age, hotness (execution frequency), and recreation rates.

## Background

[Box64](https://github.com/ptitSeb/box64) is an x86_64 emulator that uses dynamic recompilation. When memory is constrained, it purges (evicts) compiled blocks. This analysis helps determine optimal thresholds to avoid purging blocks that will be needed again soon (causing costly recreation/recompilation).

## Key Metrics

| Metric | Description |
|--------|-------------|
| **Tick** | `last_used_tick` - when the block was last executed |
| **Age** | `current_tick - last_used_tick` - how long since last use (LRU metric) |
| **Hot** | Execution count/frequency (LFU metric) |
| **Recreation** | When a purged block is needed again and must be recompiled |

## Analysis Scripts

| Script | Purpose |
|--------|---------|
| `analyze_all_logs.py` | Main analysis - per-PID and global statistics, tick/age/hot correlations |
| `analyze_threshold_dynamics.py` | Threshold sensitivity analysis, CDF of ages, recreation rate by threshold |
| `analyze_2d_heatmap.py` | 2D analysis: Age × Hot → Recreation Rate (combined LRU+LFU policy) |
| `visualize_tick_age.py` | Visualization of tick/age recreation summary data |
| `visualize_lru_lfu_conflict.py` | Shows where LRU purges HOT blocks (conflict analysis) |
| `visualize_purge_events.py` | Pie chart of SUCCESS/BLOCKED/SKIP event distribution |

## Usage

```bash
# Run main analysis (generates summary files)
python3 analyze_all_logs.py [log_directory]

# Run threshold sensitivity analysis
python3 analyze_threshold_dynamics.py [log_directory]

# Generate 2D heatmaps
python3 analyze_2d_heatmap.py

# Generate visualizations (requires summary files from analyze_all_logs.py)
python3 visualize_tick_age.py
python3 visualize_lru_lfu_conflict.py
python3 visualize_purge_events.py
```

## Log File Format

Scripts parse Box64 purge logs with naming pattern: `box64_purge_<PID>.log`

### Log Structure

```
# Box64 Dynarec Purge Log
# Format: [EVENT_TYPE] details...
# EVENT_TYPE: PURGE SUCCESS, PURGE BLOCKED, PURGE SKIP
```

### Event Types

**PURGE SUCCESS** - Block was successfully purged (evicted from cache):
```
[PURGE SUCCESS] Purging old block 0xffffb1a200c0 (x64_addr=0x6fffff57e670, hot=1, last_used_tick=1410, current_age=2155, min_age_required=1024)
```

**PURGE BLOCKED** - Block cannot be purged (currently in use):
```
[PURGE BLOCKED] Can't purge block 0xffffb1a20770 (x64_addr=0x6fffff57e580, hot=1, in_used=1, last_used_tick=1411, current_age=2154, min_age_required=1024)
```

**PURGE SKIP** - Block skipped (too young, age < threshold):
```
[PURGE SKIP] Block too young 0xffffaafdc160 (x64_addr=0x7fff0000b7b8, hot=1, in_used=0, last_used_tick=23, current_age=179, min_age_required=1024)
```

### Field Descriptions

| Field | Description |
|-------|-------------|
| `0xffffb1a200c0` | ARM64 block address (internal dynarec pointer) |
| `x64_addr` | Original x86_64 instruction address being emulated |
| `hot` | Execution count - how many times this block has been executed |
| `in_used` | 1 if block is currently being executed, 0 otherwise |
| `last_used_tick` | Global tick counter when block was last executed |
| `current_age` | `current_tick - last_used_tick` (how stale the block is) |
| `min_age_required` | Threshold age required for purging (default: 1024) |

## Analysis Modes

### Address-Based
Each unique x64 address counted once. Categories:
- **ONLY_BLOCKED**: Always in_used (core hot code)
- **PURGED_RECREATED**: Purged and came back (threshold too aggressive)
- **PURGED_GONE**: Purged and never returned (good purge decision)
- **NEVER_PURGED**: Always too young to purge

### Event-Based
Each purge event counted separately. Uses backward scan to detect recreation.

## Sample Findings

From analysis of ~130M log lines:
- Overall recreation rate: ~57.5% (indicates threshold is too aggressive)
- Hot blocks (hot > 10) have 78-98% recreation rate
- Recreated blocks are 28.8x hotter than permanently-gone blocks
- High variance across PIDs (0% to 71% recreation rate)

## Dependencies

- Python 3
- matplotlib
- numpy

## License

MIT
