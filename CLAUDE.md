# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains Python analysis scripts for Box64 dynarec block purge logs. The goal is to analyze and optimize the Box64 dynamic recompiler's cache eviction policy by studying the relationship between block age, hotness (execution frequency), and recreation rates.

**Context**: Box64 is an x86_64 emulator that uses dynamic recompilation. When memory is constrained, it purges (evicts) compiled blocks. The analysis here helps determine optimal thresholds to avoid purging blocks that will be needed again soon (recreation).

## Key Concepts

- **Tick**: `last_used_tick` - when the block was last executed
- **Age**: `current_tick - last_used_tick` - how long since the block was last used (LRU metric)
- **Hot**: Execution count/frequency (LFU metric)
- **Recreation**: When a purged block is needed again and must be recompiled (indicates premature purging)
- **Address-based**: Statistics per unique x64 address (each block counted once)
- **Event-based**: Statistics per purge event (same block can appear multiple times)

## Analysis Scripts

| Script | Purpose |
|--------|---------|
| `analyze_all_logs.py` | Main analysis - per-PID and global statistics, tick/age/hot correlations |
| `analyze_threshold_dynamics.py` | Threshold sensitivity analysis, CDF of ages, recreation rate by threshold |
| `analyze_2d_heatmap.py` | 2D analysis: Age x Hot -> Recreation Rate (finds optimal combined LRU+LFU policy) |
| `visualize_tick_age.py` | Visualization of tick/age recreation summary data |
| `visualize_lru_lfu_conflict.py` | Shows where LRU is purging HOT blocks (conflict analysis) |
| `visualize_purge_events.py` | Pie chart of SUCCESS/BLOCKED/SKIP event distribution |

## Running Scripts

All scripts can be run directly with Python 3. The default log directory is hardcoded to the current directory path.

```bash
# Run main analysis
python3 analyze_all_logs.py [log_directory]

# Run threshold analysis
python3 analyze_threshold_dynamics.py [log_directory]

# Generate 2D heatmaps
python3 analyze_2d_heatmap.py

# Generate visualizations (requires analysis summaries to exist first)
python3 visualize_tick_age.py
python3 visualize_lru_lfu_conflict.py
python3 visualize_purge_events.py
```

## Dependencies

- Python 3
- matplotlib
- numpy

## Log File Format

Scripts parse Box64 purge logs with this naming pattern: `box64_purge_<PID>.log`

Log lines contain events like:
```
[PURGE SUCCESS] ... x64_addr=0x... hot=N last_used_tick=N current_age=N
[PURGE BLOCKED] ... x64_addr=0x... hot=N (in_used > 0)
[PURGE SKIP] ... x64_addr=0x... hot=N (age < threshold)
```

## Output Files

Analysis generates:
- `*_summary.txt` - Text summaries with tables
- `*.csv` - Data exports for further analysis
- `*.png` - Visualization charts

## Key Findings from Current Data

- Overall recreation rate: ~57.5% (too aggressive)
- Hot blocks (hot > 10) have 78-98% recreation rate
- Recreated blocks are 28.8x hotter on average than permanently-gone blocks
- High variance across PIDs (0% to 71% recreation rate)
