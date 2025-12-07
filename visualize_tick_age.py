#!/usr/bin/env python3
"""
Visualize tick_age_recreation_summary.txt data
Creates charts showing recreation rates by tick and age buckets
"""

import matplotlib.pyplot as plt
import numpy as np
import re

def parse_summary_file(filepath):
    """Parse the tick_age_recreation_summary.txt file."""
    tick_data = []
    age_data = []

    with open(filepath, 'r') as f:
        content = f.read()

    # Find TABLE 1: TICK BUCKET ANALYSIS
    tick_section = re.search(r'TABLE 1: TICK BUCKET ANALYSIS.*?\n\+[-+]+\+\n(.*?)\+[-+]+\+\n\| TOTAL',
                             content, re.DOTALL)
    if tick_section:
        lines = tick_section.group(1).strip().split('\n')
        for line in lines:
            if line.startswith('|') and 'Tick' not in line:
                parts = [p.strip() for p in line.split('|')[1:-1]]
                if len(parts) >= 6:
                    bucket = parts[0]
                    purged = int(parts[1].replace(',', ''))
                    recreated = int(parts[3].replace(',', ''))
                    gone = int(parts[4].replace(',', ''))
                    rec_rate = float(parts[5].replace('%', ''))
                    tick_data.append({
                        'bucket': bucket,
                        'purged': purged,
                        'recreated': recreated,
                        'gone': gone,
                        'rec_rate': rec_rate
                    })

    # Find TABLE 2: AGE BUCKET ANALYSIS
    age_section = re.search(r'TABLE 2: AGE BUCKET ANALYSIS.*?\n\+[-+]+\+\n(.*?)\+[-+]+\+\n\| TOTAL',
                            content, re.DOTALL)
    if age_section:
        lines = age_section.group(1).strip().split('\n')
        for line in lines:
            if line.startswith('|') and 'Age' not in line:
                parts = [p.strip() for p in line.split('|')[1:-1]]
                if len(parts) >= 6:
                    bucket = parts[0]
                    purged = int(parts[1].replace(',', ''))
                    recreated = int(parts[3].replace(',', ''))
                    gone = int(parts[4].replace(',', ''))
                    rec_rate = float(parts[5].replace('%', ''))
                    age_data.append({
                        'bucket': bucket,
                        'purged': purged,
                        'recreated': recreated,
                        'gone': gone,
                        'rec_rate': rec_rate
                    })

    return tick_data, age_data


def create_visualization(tick_data, age_data, output_path):
    """Create a comprehensive visualization."""
    # Filter out zero-purge buckets for cleaner charts
    tick_data_filtered = [d for d in tick_data if d['purged'] > 0]
    age_data_filtered = [d for d in age_data if d['purged'] > 0]

    fig, axes = plt.subplots(2, 3, figsize=(18, 12))
    fig.suptitle('Box64 Dynarec Purge Analysis: Tick & Age vs Recreation Rate\n(Event-Based: Each purge event counted separately)',
                 fontsize=14, fontweight='bold')

    # Color scheme
    colors_purged = '#3498db'
    colors_recreated = '#e74c3c'
    colors_gone = '#2ecc71'
    colors_rate = '#9b59b6'

    # === TICK CHARTS (Top Row) ===

    # 1. Tick: Purge Volume Bar Chart
    ax1 = axes[0, 0]
    buckets = [d['bucket'] for d in tick_data_filtered]
    purged = [d['purged'] for d in tick_data_filtered]
    x = np.arange(len(buckets))
    ax1.bar(x, purged, color=colors_purged, alpha=0.8)
    ax1.set_xlabel('Last Used Tick')
    ax1.set_ylabel('Purge Events')
    ax1.set_title('TICK: Purge Volume by Last-Used-Tick')
    ax1.set_xticks(x[::3])
    ax1.set_xticklabels([buckets[i] for i in range(0, len(buckets), 3)], rotation=45, ha='right', fontsize=8)
    ax1.grid(axis='y', alpha=0.3)

    # 2. Tick: Stacked Bar (Recreated vs Gone)
    ax2 = axes[0, 1]
    recreated = [d['recreated'] for d in tick_data_filtered]
    gone = [d['gone'] for d in tick_data_filtered]
    ax2.bar(x, recreated, color=colors_recreated, alpha=0.8, label='Recreated')
    ax2.bar(x, gone, bottom=recreated, color=colors_gone, alpha=0.8, label='Gone')
    ax2.set_xlabel('Last Used Tick')
    ax2.set_ylabel('Purge Events')
    ax2.set_title('TICK: Recreated vs Gone')
    ax2.set_xticks(x[::3])
    ax2.set_xticklabels([buckets[i] for i in range(0, len(buckets), 3)], rotation=45, ha='right', fontsize=8)
    ax2.legend(loc='upper left')
    ax2.grid(axis='y', alpha=0.3)

    # 3. Tick: Recreation Rate Line
    ax3 = axes[0, 2]
    rec_rates = [d['rec_rate'] for d in tick_data_filtered]
    ax3.plot(x, rec_rates, color=colors_rate, linewidth=2, marker='o', markersize=4)
    ax3.axhline(y=50, color='red', linestyle='--', alpha=0.5, label='50%')
    ax3.fill_between(x, rec_rates, alpha=0.3, color=colors_rate)
    ax3.set_xlabel('Last Used Tick')
    ax3.set_ylabel('Recreation Rate (%)')
    ax3.set_title('TICK: Recreation Rate by Last-Used-Tick')
    ax3.set_xticks(x[::3])
    ax3.set_xticklabels([buckets[i] for i in range(0, len(buckets), 3)], rotation=45, ha='right', fontsize=8)
    ax3.set_ylim(0, 100)
    ax3.legend(loc='lower right')
    ax3.grid(alpha=0.3)

    # === AGE CHARTS (Bottom Row) ===

    # 4. Age: Purge Volume Bar Chart
    ax4 = axes[1, 0]
    buckets_age = [d['bucket'] for d in age_data_filtered]
    purged_age = [d['purged'] for d in age_data_filtered]
    x_age = np.arange(len(buckets_age))
    ax4.bar(x_age, purged_age, color=colors_purged, alpha=0.8)
    ax4.set_xlabel('Age (current_tick - last_used_tick)')
    ax4.set_ylabel('Purge Events')
    ax4.set_title('AGE: Purge Volume by Block Age')
    ax4.set_xticks(x_age[::2])
    ax4.set_xticklabels([buckets_age[i] for i in range(0, len(buckets_age), 2)], rotation=45, ha='right', fontsize=8)
    ax4.grid(axis='y', alpha=0.3)

    # 5. Age: Stacked Bar (Recreated vs Gone)
    ax5 = axes[1, 1]
    recreated_age = [d['recreated'] for d in age_data_filtered]
    gone_age = [d['gone'] for d in age_data_filtered]
    ax5.bar(x_age, recreated_age, color=colors_recreated, alpha=0.8, label='Recreated')
    ax5.bar(x_age, gone_age, bottom=recreated_age, color=colors_gone, alpha=0.8, label='Gone')
    ax5.set_xlabel('Age (current_tick - last_used_tick)')
    ax5.set_ylabel('Purge Events')
    ax5.set_title('AGE: Recreated vs Gone')
    ax5.set_xticks(x_age[::2])
    ax5.set_xticklabels([buckets_age[i] for i in range(0, len(buckets_age), 2)], rotation=45, ha='right', fontsize=8)
    ax5.legend(loc='upper right')
    ax5.grid(axis='y', alpha=0.3)

    # 6. Age: Recreation Rate Line
    ax6 = axes[1, 2]
    rec_rates_age = [d['rec_rate'] for d in age_data_filtered]
    ax6.plot(x_age, rec_rates_age, color=colors_rate, linewidth=2, marker='o', markersize=4)
    ax6.axhline(y=50, color='red', linestyle='--', alpha=0.5, label='50%')
    ax6.fill_between(x_age, rec_rates_age, alpha=0.3, color=colors_rate)
    ax6.set_xlabel('Age (current_tick - last_used_tick)')
    ax6.set_ylabel('Recreation Rate (%)')
    ax6.set_title('AGE: Recreation Rate by Block Age')
    ax6.set_xticks(x_age[::2])
    ax6.set_xticklabels([buckets_age[i] for i in range(0, len(buckets_age), 2)], rotation=45, ha='right', fontsize=8)
    ax6.set_ylim(0, 100)
    ax6.legend(loc='upper right')
    ax6.grid(alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Saved visualization to: {output_path}")


def create_combined_rate_chart(tick_data, age_data, output_path):
    """Create a combined recreation rate comparison chart."""
    tick_filtered = [d for d in tick_data if d['purged'] > 0]
    age_filtered = [d for d in age_data if d['purged'] > 0]

    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    fig.suptitle('Recreation Rate Analysis: TICK vs AGE\n(Lower is better - fewer wasted purges)',
                 fontsize=14, fontweight='bold')

    # Left: TICK recreation rate with volume as bubble size
    ax1 = axes[0]
    x_tick = range(len(tick_filtered))
    sizes = [d['purged'] / 500 for d in tick_filtered]  # Scale for visibility
    colors = [d['rec_rate'] for d in tick_filtered]

    scatter = ax1.scatter(x_tick, [d['rec_rate'] for d in tick_filtered],
                          s=sizes, c=colors, cmap='RdYlGn_r', alpha=0.7,
                          edgecolors='black', linewidth=0.5)
    ax1.axhline(y=50, color='red', linestyle='--', alpha=0.7, label='50%')
    ax1.axhline(y=70, color='orange', linestyle='--', alpha=0.5, label='70%')
    ax1.set_xlabel('Tick Bucket Index')
    ax1.set_ylabel('Recreation Rate (%)')
    ax1.set_title('TICK: Recreation Rate\n(bubble size = purge volume)')
    ax1.set_ylim(0, 100)
    ax1.legend(loc='lower right')
    ax1.grid(alpha=0.3)

    # Annotate key buckets
    for i, d in enumerate(tick_filtered):
        if d['purged'] > 30000 or d['rec_rate'] > 80:
            ax1.annotate(d['bucket'], (i, d['rec_rate']), fontsize=7,
                        xytext=(5, 5), textcoords='offset points')

    plt.colorbar(scatter, ax=ax1, label='Recreation Rate %')

    # Right: AGE recreation rate with volume as bubble size
    ax2 = axes[1]
    x_age = range(len(age_filtered))
    sizes_age = [d['purged'] / 500 for d in age_filtered]
    colors_age = [d['rec_rate'] for d in age_filtered]

    scatter2 = ax2.scatter(x_age, [d['rec_rate'] for d in age_filtered],
                           s=sizes_age, c=colors_age, cmap='RdYlGn_r', alpha=0.7,
                           edgecolors='black', linewidth=0.5)
    ax2.axhline(y=50, color='red', linestyle='--', alpha=0.7, label='50%')
    ax2.axhline(y=70, color='orange', linestyle='--', alpha=0.5, label='70%')
    ax2.set_xlabel('Age Bucket Index')
    ax2.set_ylabel('Recreation Rate (%)')
    ax2.set_title('AGE: Recreation Rate\n(bubble size = purge volume)')
    ax2.set_ylim(0, 100)
    ax2.legend(loc='upper right')
    ax2.grid(alpha=0.3)

    # Annotate key buckets
    for i, d in enumerate(age_filtered):
        if d['purged'] > 30000 or d['rec_rate'] > 70:
            ax2.annotate(d['bucket'], (i, d['rec_rate']), fontsize=7,
                        xytext=(5, 5), textcoords='offset points')

    plt.colorbar(scatter2, ax=ax2, label='Recreation Rate %')

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Saved combined rate chart to: {output_path}")


def create_cdf_chart(tick_data, age_data, output_path):
    """Create CDF (Cumulative Distribution Function) charts."""
    tick_filtered = [d for d in tick_data if d['purged'] > 0]
    age_filtered = [d for d in age_data if d['purged'] > 0]

    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    fig.suptitle('Cumulative Distribution: Purge Events & Recreation', fontsize=14, fontweight='bold')

    # TICK CDF
    ax1 = axes[0]
    total_purged = sum(d['purged'] for d in tick_filtered)
    total_recreated = sum(d['recreated'] for d in tick_filtered)

    cum_purged = np.cumsum([d['purged'] for d in tick_filtered]) / total_purged * 100
    cum_recreated = np.cumsum([d['recreated'] for d in tick_filtered]) / total_recreated * 100

    x = range(len(tick_filtered))
    ax1.plot(x, cum_purged, 'b-', linewidth=2, label='Cumulative Purged')
    ax1.plot(x, cum_recreated, 'r-', linewidth=2, label='Cumulative Recreated')
    ax1.axhline(y=50, color='gray', linestyle='--', alpha=0.5)
    ax1.axhline(y=80, color='gray', linestyle='--', alpha=0.5)
    ax1.set_xlabel('Tick Bucket')
    ax1.set_ylabel('Cumulative %')
    ax1.set_title('TICK: CDF of Purge Events')
    ax1.set_xticks(x[::3])
    ax1.set_xticklabels([tick_filtered[i]['bucket'] for i in range(0, len(tick_filtered), 3)],
                        rotation=45, ha='right', fontsize=8)
    ax1.legend()
    ax1.grid(alpha=0.3)
    ax1.set_ylim(0, 100)

    # AGE CDF
    ax2 = axes[1]
    total_purged_age = sum(d['purged'] for d in age_filtered)
    total_recreated_age = sum(d['recreated'] for d in age_filtered)

    cum_purged_age = np.cumsum([d['purged'] for d in age_filtered]) / total_purged_age * 100
    cum_recreated_age = np.cumsum([d['recreated'] for d in age_filtered]) / total_recreated_age * 100

    x_age = range(len(age_filtered))
    ax2.plot(x_age, cum_purged_age, 'b-', linewidth=2, label='Cumulative Purged')
    ax2.plot(x_age, cum_recreated_age, 'r-', linewidth=2, label='Cumulative Recreated')
    ax2.axhline(y=50, color='gray', linestyle='--', alpha=0.5)
    ax2.axhline(y=80, color='gray', linestyle='--', alpha=0.5)
    ax2.set_xlabel('Age Bucket')
    ax2.set_ylabel('Cumulative %')
    ax2.set_title('AGE: CDF of Purge Events')
    ax2.set_xticks(x_age[::2])
    ax2.set_xticklabels([age_filtered[i]['bucket'] for i in range(0, len(age_filtered), 2)],
                        rotation=45, ha='right', fontsize=8)
    ax2.legend()
    ax2.grid(alpha=0.3)
    ax2.set_ylim(0, 100)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Saved CDF chart to: {output_path}")


def main():
    import os

    base_dir = "/Users/devaraja/Downloads/Box64 tick hot"
    input_file = os.path.join(base_dir, "tick_age_recreation_summary.txt")

    print(f"Reading: {input_file}")
    tick_data, age_data = parse_summary_file(input_file)

    print(f"Parsed {len(tick_data)} tick buckets, {len(age_data)} age buckets")

    # Create visualizations
    create_visualization(tick_data, age_data,
                        os.path.join(base_dir, "tick_age_visualization.png"))

    create_combined_rate_chart(tick_data, age_data,
                               os.path.join(base_dir, "tick_age_rate_comparison.png"))

    create_cdf_chart(tick_data, age_data,
                     os.path.join(base_dir, "tick_age_cdf.png"))

    print("\nDone! Generated 3 visualization files.")


if __name__ == "__main__":
    main()
