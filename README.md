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

Expected log line formats:
```
[PURGE SUCCESS] ... x64_addr=0x... hot=N last_used_tick=N current_age=N
[PURGE BLOCKED] ... x64_addr=0x... hot=N (in_used > 0)
[PURGE SKIP] ... x64_addr=0x... hot=N (age < threshold)
```

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
