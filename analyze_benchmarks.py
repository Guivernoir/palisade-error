#!/usr/bin/env python3
"""
Benchmark Results Analyzer
Parses benchmark_memory_results.txt and generates comprehensive analysis with charts.
"""

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Optional
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import pandas as pd
import numpy as np
from datetime import datetime


@dataclass
class BenchmarkEntry:
    """Represents a single benchmark measurement."""
    name: str
    time_ns: float
    alloc_bytes: int
    alloc_calls: int
    dealloc_bytes: int
    dealloc_calls: int
    net_bytes: int
    
    @property
    def time_us(self) -> float:
        """Time in microseconds."""
        return self.time_ns / 1_000.0
    
    @property
    def time_ms(self) -> float:
        """Time in milliseconds."""
        return self.time_ns / 1_000_000.0
    
    @property
    def category(self) -> str:
        """Extract category from benchmark name."""
        name_lower = self.name.lower()
        if 'error' in name_lower and 'creation' in name_lower:
            return 'Error Creation'
        elif 'metadata' in name_lower:
            return 'Metadata'
        elif 'log' in name_lower:
            return 'Logging'
        elif 'display' in name_lower or 'format' in name_lower:
            return 'Display'
        elif 'honeypot' in name_lower:
            return 'Honeypot'
        elif 'timing' in name_lower:
            return 'Timing'
        elif 'obfuscation' in name_lower:
            return 'Obfuscation'
        elif 'ring' in name_lower or 'buffer' in name_lower:
            return 'Ring Buffer'
        elif 'allocation' in name_lower or 'memory' in name_lower:
            return 'Memory'
        elif 'unicode' in name_lower or 'chain' in name_lower:
            return 'Edge Cases'
        else:
            return 'Other'


class BenchmarkParser:
    """Parses benchmark results from text file."""
    
    # Pattern: name │ Time: 123.45 ns │ Alloc: 256 B (2 calls) │ Dealloc: 256 B (2 calls) │ Net: 0 B
    PATTERN = re.compile(
        r'^(?P<name>.+?)\s+│\s+Time:\s+(?P<time>[\d.]+)\s+(?P<unit>\w+)\s+│\s+'
        r'Alloc:\s+(?P<alloc>\d+)\s+B\s+\(\s*(?P<alloc_calls>\d+)\s+calls\)\s+│\s+'
        r'Dealloc:\s+(?P<dealloc>\d+)\s+B\s+\(\s*(?P<dealloc_calls>\d+)\s+calls\)\s+│\s+'
        r'Net:\s+(?P<net>\d+)\s+B'
    )
    
    @classmethod
    def parse_file(cls, filepath: Path) -> List[BenchmarkEntry]:
        """Parse benchmark results file."""
        entries: List[BenchmarkEntry] = []
        
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('═') or 'timestamp' in line.lower():
                    continue
                
                match = cls.PATTERN.match(line)
                if match:
                    data = match.groupdict()
                    
                    # Convert time to nanoseconds
                    time_val = float(data['time'])
                    unit = data['unit']
                    if unit == 'ns':
                        time_ns = time_val
                    elif unit == 'µs' or unit == 'us':
                        time_ns = time_val * 1_000
                    elif unit == 'ms':
                        time_ns = time_val * 1_000_000
                    elif unit == 's':
                        time_ns = time_val * 1_000_000_000
                    else:
                        time_ns = time_val  # fallback
                    
                    entry = BenchmarkEntry(
                        name=data['name'].strip(),
                        time_ns=time_ns,
                        alloc_bytes=int(data['alloc']),
                        alloc_calls=int(data['alloc_calls']),
                        dealloc_bytes=int(data['dealloc']),
                        dealloc_calls=int(data['dealloc_calls']),
                        net_bytes=int(data['net'])
                    )
                    entries.append(entry)
        
        return entries


class BenchmarkAnalyzer:
    """Analyzes and visualizes benchmark results."""
    
    def __init__(self, entries: List[BenchmarkEntry]):
        self.entries = entries
        self.df = self._create_dataframe()
    
    def _create_dataframe(self) -> pd.DataFrame:
        """Convert entries to pandas DataFrame."""
        data = {
            'name': [e.name for e in self.entries],
            'category': [e.category for e in self.entries],
            'time_ns': [e.time_ns for e in self.entries],
            'time_us': [e.time_us for e in self.entries],
            'time_ms': [e.time_ms for e in self.entries],
            'alloc_bytes': [e.alloc_bytes for e in self.entries],
            'alloc_calls': [e.alloc_calls for e in self.entries],
            'dealloc_bytes': [e.dealloc_bytes for e in self.entries],
            'dealloc_calls': [e.dealloc_calls for e in self.entries],
            'net_bytes': [e.net_bytes for e in self.entries],
        }
        return pd.DataFrame(data)
    
    def print_summary(self):
        """Print summary statistics."""
        print("\n" + "="*80)
        print("BENCHMARK SUMMARY STATISTICS")
        print("="*80)
        
        print(f"\nTotal Benchmarks: {len(self.entries)}")
        print(f"Categories: {', '.join(sorted(self.df['category'].unique()))}")
        
        print("\n--- Timing Statistics (microseconds) ---")
        print(f"Mean:   {self.df['time_us'].mean():.2f} µs")
        print(f"Median: {self.df['time_us'].median():.2f} µs")
        print(f"Min:    {self.df['time_us'].min():.2f} µs  ({self.df.loc[self.df['time_us'].idxmin(), 'name']})")
        print(f"Max:    {self.df['time_us'].max():.2f} µs  ({self.df.loc[self.df['time_us'].idxmax(), 'name']})")
        
        print("\n--- Memory Allocation Statistics ---")
        print(f"Mean Alloc:   {self.df['alloc_bytes'].mean():.0f} bytes")
        print(f"Median Alloc: {self.df['alloc_bytes'].median():.0f} bytes")
        print(f"Max Alloc:    {self.df['alloc_bytes'].max()} bytes  ({self.df.loc[self.df['alloc_bytes'].idxmax(), 'name']})")
        
        print("\n--- Top 10 Slowest Benchmarks ---")
        top_slow = self.df.nlargest(10, 'time_us')[['name', 'time_us', 'alloc_bytes']]
        for idx, row in top_slow.iterrows():
            print(f"  {row['name']:<45} {row['time_us']:>8.2f} µs  {row['alloc_bytes']:>8} B")
        
        print("\n--- Top 10 Most Memory Intensive ---")
        top_mem = self.df.nlargest(10, 'alloc_bytes')[['name', 'alloc_bytes', 'time_us']]
        for idx, row in top_mem.iterrows():
            print(f"  {row['name']:<45} {row['alloc_bytes']:>8} B  {row['time_us']:>8.2f} µs")
        
        print("\n--- Category Breakdown ---")
        category_stats = self.df.groupby('category').agg({
            'time_us': ['count', 'mean', 'median'],
            'alloc_bytes': ['mean', 'median']
        }).round(2)
        print(category_stats.to_string())
    
    def create_charts(self, output_dir: Path):
        """Generate all analysis charts."""
        output_dir.mkdir(exist_ok=True)
        
        # Set style
        plt.style.use('seaborn-v0_8-darkgrid')
        
        self._chart_timing_overview(output_dir)
        self._chart_memory_overview(output_dir)
        self._chart_category_comparison(output_dir)
        self._chart_timing_vs_memory(output_dir)
        self._chart_allocation_efficiency(output_dir)
        self._chart_top_performers(output_dir)
        
        print(f"\n✓ Charts saved to: {output_dir.absolute()}")
    
    def _chart_timing_overview(self, output_dir: Path):
        """Chart: Timing distribution."""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
        
        # Histogram
        ax1.hist(self.df['time_us'], bins=30, color='steelblue', edgecolor='black', alpha=0.7)
        ax1.set_xlabel('Time (µs)', fontsize=12)
        ax1.set_ylabel('Frequency', fontsize=12)
        ax1.set_title('Timing Distribution', fontsize=14, fontweight='bold')
        ax1.grid(axis='y', alpha=0.3)
        
        # Box plot by category
        categories = sorted(self.df['category'].unique())
        data_by_cat = [self.df[self.df['category'] == cat]['time_us'].values for cat in categories]
        bp = ax2.boxplot(data_by_cat, labels=categories, patch_artist=True)
        for patch in bp['boxes']:
            patch.set_facecolor('lightblue')
        ax2.set_xlabel('Category', fontsize=12)
        ax2.set_ylabel('Time (µs)', fontsize=12)
        ax2.set_title('Timing by Category', fontsize=14, fontweight='bold')
        ax2.tick_params(axis='x', rotation=45)
        ax2.grid(axis='y', alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(output_dir / '01_timing_overview.png', dpi=150, bbox_inches='tight')
        plt.close()
    
    def _chart_memory_overview(self, output_dir: Path):
        """Chart: Memory allocation overview."""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
        
        # Allocation vs Deallocation
        x = np.arange(len(self.entries))
        width = 0.4
        ax1.bar(x - width/2, self.df['alloc_bytes'], width, label='Allocated', color='coral', alpha=0.8)
        ax1.bar(x + width/2, self.df['dealloc_bytes'], width, label='Deallocated', color='lightgreen', alpha=0.8)
        ax1.set_xlabel('Benchmark Index', fontsize=12)
        ax1.set_ylabel('Bytes', fontsize=12)
        ax1.set_title('Memory Allocation vs Deallocation', fontsize=14, fontweight='bold')
        ax1.legend()
        ax1.grid(axis='y', alpha=0.3)
        
        # Net memory by category
        net_by_cat = self.df.groupby('category')['net_bytes'].sum().sort_values()
        net_by_cat.plot(kind='barh', ax=ax2, color='mediumpurple')
        ax2.set_xlabel('Net Bytes', fontsize=12)
        ax2.set_ylabel('Category', fontsize=12)
        ax2.set_title('Net Memory Change by Category', fontsize=14, fontweight='bold')
        ax2.grid(axis='x', alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(output_dir / '02_memory_overview.png', dpi=150, bbox_inches='tight')
        plt.close()
    
    def _chart_category_comparison(self, output_dir: Path):
        """Chart: Compare categories on multiple metrics."""
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        
        cat_stats = self.df.groupby('category').agg({
            'time_us': 'mean',
            'alloc_bytes': 'mean',
            'alloc_calls': 'mean',
            'net_bytes': 'sum'
        }).round(2)
        
        # Mean timing
        cat_stats['time_us'].sort_values().plot(kind='barh', ax=ax1, color='steelblue')
        ax1.set_xlabel('Mean Time (µs)', fontsize=11)
        ax1.set_title('Average Timing by Category', fontsize=12, fontweight='bold')
        ax1.grid(axis='x', alpha=0.3)
        
        # Mean allocation
        cat_stats['alloc_bytes'].sort_values().plot(kind='barh', ax=ax2, color='coral')
        ax2.set_xlabel('Mean Allocated Bytes', fontsize=11)
        ax2.set_title('Average Memory Allocation by Category', fontsize=12, fontweight='bold')
        ax2.grid(axis='x', alpha=0.3)
        
        # Mean allocation calls
        cat_stats['alloc_calls'].sort_values().plot(kind='barh', ax=ax3, color='mediumseagreen')
        ax3.set_xlabel('Mean Allocation Calls', fontsize=11)
        ax3.set_title('Average Allocation Calls by Category', fontsize=12, fontweight='bold')
        ax3.grid(axis='x', alpha=0.3)
        
        # Benchmark count per category
        count_by_cat = self.df['category'].value_counts().sort_values()
        count_by_cat.plot(kind='barh', ax=ax4, color='mediumpurple')
        ax4.set_xlabel('Number of Benchmarks', fontsize=11)
        ax4.set_title('Benchmark Count by Category', fontsize=12, fontweight='bold')
        ax4.grid(axis='x', alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(output_dir / '03_category_comparison.png', dpi=150, bbox_inches='tight')
        plt.close()
    
    def _chart_timing_vs_memory(self, output_dir: Path):
        """Chart: Scatter plot of timing vs memory."""
        fig, ax = plt.subplots(figsize=(12, 8))
        
        categories = self.df['category'].unique()
        colors = plt.cm.tab10(np.linspace(0, 1, len(categories)))
        
        for cat, color in zip(categories, colors):
            mask = self.df['category'] == cat
            ax.scatter(
                self.df[mask]['time_us'],
                self.df[mask]['alloc_bytes'],
                label=cat,
                alpha=0.6,
                s=100,
                color=color,
                edgecolors='black',
                linewidth=0.5
            )
        
        ax.set_xlabel('Time (µs)', fontsize=12)
        ax.set_ylabel('Allocated Bytes', fontsize=12)
        ax.set_title('Timing vs Memory Allocation', fontsize=14, fontweight='bold')
        ax.legend(loc='best', fontsize=10)
        ax.grid(True, alpha=0.3)
        
        # Log scale if range is large
        if self.df['time_us'].max() / self.df['time_us'].min() > 100:
            ax.set_xscale('log')
        if self.df['alloc_bytes'].max() / (self.df['alloc_bytes'].min() + 1) > 100:
            ax.set_yscale('log')
        
        plt.tight_layout()
        plt.savefig(output_dir / '04_timing_vs_memory.png', dpi=150, bbox_inches='tight')
        plt.close()
    
    def _chart_allocation_efficiency(self, output_dir: Path):
        """Chart: Allocation efficiency metrics."""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
        
        # Bytes per allocation call
        self.df['bytes_per_alloc'] = self.df['alloc_bytes'] / (self.df['alloc_calls'] + 0.001)
        top_bpa = self.df.nlargest(15, 'bytes_per_alloc')[['name', 'bytes_per_alloc']]
        
        y_pos = np.arange(len(top_bpa))
        ax1.barh(y_pos, top_bpa['bytes_per_alloc'], color='teal', alpha=0.7)
        ax1.set_yticks(y_pos)
        ax1.set_yticklabels([name[:40] for name in top_bpa['name']], fontsize=9)
        ax1.set_xlabel('Bytes per Allocation Call', fontsize=11)
        ax1.set_title('Top 15: Largest Average Allocations', fontsize=12, fontweight='bold')
        ax1.grid(axis='x', alpha=0.3)
        
        # Time per allocated byte
        self.df['ns_per_byte'] = self.df['time_ns'] / (self.df['alloc_bytes'] + 0.001)
        top_tpb = self.df.nlargest(15, 'ns_per_byte')[['name', 'ns_per_byte']]
        
        y_pos = np.arange(len(top_tpb))
        ax2.barh(y_pos, top_tpb['ns_per_byte'], color='darkgoldenrod', alpha=0.7)
        ax2.set_yticks(y_pos)
        ax2.set_yticklabels([name[:40] for name in top_tpb['name']], fontsize=9)
        ax2.set_xlabel('Nanoseconds per Byte Allocated', fontsize=11)
        ax2.set_title('Top 15: Slowest per Byte Allocated', fontsize=12, fontweight='bold')
        ax2.grid(axis='x', alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(output_dir / '05_allocation_efficiency.png', dpi=150, bbox_inches='tight')
        plt.close()
    
    def _chart_top_performers(self, output_dir: Path):
        """Chart: Best and worst performers."""
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        
        # Fastest 10
        fastest = self.df.nsmallest(10, 'time_us')[['name', 'time_us']].sort_values('time_us')
        y_pos = np.arange(len(fastest))
        ax1.barh(y_pos, fastest['time_us'], color='green', alpha=0.7)
        ax1.set_yticks(y_pos)
        ax1.set_yticklabels([name[:35] for name in fastest['name']], fontsize=9)
        ax1.set_xlabel('Time (µs)', fontsize=11)
        ax1.set_title('Top 10 Fastest Benchmarks', fontsize=12, fontweight='bold')
        ax1.grid(axis='x', alpha=0.3)
        
        # Slowest 10
        slowest = self.df.nlargest(10, 'time_us')[['name', 'time_us']].sort_values('time_us', ascending=False)
        y_pos = np.arange(len(slowest))
        ax2.barh(y_pos, slowest['time_us'], color='red', alpha=0.7)
        ax2.set_yticks(y_pos)
        ax2.set_yticklabels([name[:35] for name in slowest['name']], fontsize=9)
        ax2.set_xlabel('Time (µs)', fontsize=11)
        ax2.set_title('Top 10 Slowest Benchmarks', fontsize=12, fontweight='bold')
        ax2.grid(axis='x', alpha=0.3)
        
        # Least memory
        least_mem = self.df.nsmallest(10, 'alloc_bytes')[['name', 'alloc_bytes']].sort_values('alloc_bytes')
        y_pos = np.arange(len(least_mem))
        ax3.barh(y_pos, least_mem['alloc_bytes'], color='lightblue', alpha=0.7)
        ax3.set_yticks(y_pos)
        ax3.set_yticklabels([name[:35] for name in least_mem['name']], fontsize=9)
        ax3.set_xlabel('Allocated Bytes', fontsize=11)
        ax3.set_title('Top 10 Least Memory Usage', fontsize=12, fontweight='bold')
        ax3.grid(axis='x', alpha=0.3)
        
        # Most memory
        most_mem = self.df.nlargest(10, 'alloc_bytes')[['name', 'alloc_bytes']].sort_values('alloc_bytes', ascending=False)
        y_pos = np.arange(len(most_mem))
        ax4.barh(y_pos, most_mem['alloc_bytes'], color='orange', alpha=0.7)
        ax4.set_yticks(y_pos)
        ax4.set_yticklabels([name[:35] for name in most_mem['name']], fontsize=9)
        ax4.set_xlabel('Allocated Bytes', fontsize=11)
        ax4.set_title('Top 10 Highest Memory Usage', fontsize=12, fontweight='bold')
        ax4.grid(axis='x', alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(output_dir / '06_top_performers.png', dpi=150, bbox_inches='tight')
        plt.close()
    
    def export_csv(self, output_path: Path):
        """Export data to CSV for further analysis."""
        self.df.to_csv(output_path, index=False)
        print(f"✓ Data exported to: {output_path.absolute()}")


def main():
    """Main entry point."""
    input_file = Path("benchmark_memory_results.txt")
    output_dir = Path("benchmark_analysis")
    
    # Check if input exists
    if not input_file.exists():
        print(f"Error: {input_file} not found!")
        print("Please run the benchmarks first to generate results.")
        sys.exit(1)
    
    print("="*80)
    print("BENCHMARK ANALYSIS TOOL")
    print("="*80)
    print(f"\nParsing: {input_file}")
    
    # Parse results
    entries = BenchmarkParser.parse_file(input_file)
    
    if not entries:
        print("Error: No benchmark entries found in file!")
        sys.exit(1)
    
    print(f"Found {len(entries)} benchmark entries")
    
    # Analyze
    analyzer = BenchmarkAnalyzer(entries)
    
    # Print summary
    analyzer.print_summary()
    
    # Generate charts
    print(f"\nGenerating charts in: {output_dir}")
    analyzer.create_charts(output_dir)
    
    # Export CSV
    csv_path = output_dir / "benchmark_data.csv"
    analyzer.export_csv(csv_path)
    
    print("\n" + "="*80)
    print("ANALYSIS COMPLETE")
    print("="*80)
    print(f"\nOutput directory: {output_dir.absolute()}")
    print("\nGenerated files:")
    print("  • 01_timing_overview.png       - Timing distribution and box plots")
    print("  • 02_memory_overview.png       - Memory allocation patterns")
    print("  • 03_category_comparison.png   - Category-level metrics")
    print("  • 04_timing_vs_memory.png      - Correlation scatter plot")
    print("  • 05_allocation_efficiency.png - Efficiency metrics")
    print("  • 06_top_performers.png        - Best/worst benchmarks")
    print("  • benchmark_data.csv           - Raw data export")
    print("\n")


if __name__ == "__main__":
    main()