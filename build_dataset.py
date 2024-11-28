import re
import numpy as np

PAGE_SIZE = 4096

page_stats = defaultdict(lambda: {
    "page_faults": 0,
    "tlb_load_misses": 0,
    "tlb_store_misses": 0,
    "cache_misses": 0,
    "cache_references": 0,
    "context_switches": 0,
    "instructions": 0,
    "branches": 0,
    "branch_misses": 0,
})

with open('perf_ouput.txt', 'r') as f:
    for line in f:
        if "page-faults" in line:
            match = re.search(r"address (0x[0-9a-f]+)", line)
            if match:
                address = int(match.group(1), 16)
                page = address // PAGE_SIZE
                page_stats[page]["page_faults"] += 1
        elif "dTLB-load-misses" in line:
            match = re.search(r"address (0x[0-9a-f]+)", line)
            if match:
                address = int(match.group(1), 16)
                page = address // PAGE_SIZE
                page_stats[page]["tlb_load_misses"] += 1
        elif "dTLB-store-misses" in line:
            match = re.search(r"address (0x[0-9a-f]+)", line)
            if match:
                address = int(match.group(1), 16)
                page = address // PAGE_SIZE
                page_stats[page]["tlb_store_misses"] += 1
        elif "cache-misses" in line:
            match = re.search(r"address (0x[0-9a-f]+)", line)
            if match:
                address = int(match.group(1), 16)
                page = address // PAGE_SIZE
                page_stats[page]["cache_misses"] += 1
        elif "cache-references" in line:
            match = re.search(r"address (0x[0-9a-f]+)", line)
            if match:
                address = int(match.group(1), 16)
                page = address // PAGE_SIZE
                page_stats[page]["cache_references"] += 1
        elif "context-switches" in line:
            page_stats["global"]["context_switches"] += 1
        elif "instructions" in line:
            page_stats["global"]["instructions"] += 1
        elif "branches" in line:
            page_stats["global"]["branches"] += 1
        elif "branch-misses" in line:
            page_stats["global"]["branch_misses"] += 1

# Compute other metrics
# Compute derived metrics
for page, stats in page_stats.items():
    stats["cache_miss_rate"] = (
        stats["cache_misses"] / stats["cache_references"]
        if stats["cache_references"] > 0
        else 0
    )
    stats["branch_miss_rate"] = (
        stats["branch_misses"] / stats["branches"]
        if stats["branches"] > 0
        else 0
    )

# Aggregated stats
print("Page-Level Statistics:")
for page, stats in page_stats.items():
    print(f"Page {page}: {stats}")

"""
perf record -e page-faults,dTLB-load-misses,dTLB-store-misses,cache-references,cache-misses,context-switches,instructions,branches,branch-misses ./your_workload
"""