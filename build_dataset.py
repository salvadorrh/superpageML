import re
from collections import defaultdict
import pandas as pd

PAGE_SIZE = 4096    # 4KB
NUM_PAGES = 1000    # Num pages in workload

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

global_stats = {
    "context_switches": 0,
    "instructions": 0,
    "branches": 0,
    "branch_misses": 0,    
}

address_pattern = re.compile(r"address (?:0x)?([0-9a-fA-F]+)")

# Read perf output file (derived from perf.data)
with open('perf_output.txt', 'r') as f:
    for line in f:
        if "page-faults" in line:
            match = address_pattern.search(line)
            if match:
                address = int(match.group(1), 16)
                page = address // PAGE_SIZE
                page_stats[page]["page_faults"] += 1
        elif "dTLB-load-misses" in line:
            match = address_pattern.search(line)
            if match:
                address = int(match.group(1), 16)
                page = address // PAGE_SIZE
                page_stats[page]["tlb_load_misses"] += 1
        elif "dTLB-store-misses" in line:
            match = address_pattern.search(line)
            if match:
                address = int(match.group(1), 16)
                page = address // PAGE_SIZE
                page_stats[page]["tlb_store_misses"] += 1
        elif "cache-misses" in line:
            match = address_pattern.search(line)
            if match:
                address = int(match.group(1), 16)
                page = address // PAGE_SIZE
                page_stats[page]["cache_misses"] += 1
        elif "cache-references" in line:
            match = address_pattern.search(line)
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

# Compute derived metrics
data = []
for page in range(NUM_PAGES):
    stats = page_stats.get(page, {
        "page_faults": 0,
        "tlb_load_misses": 0,
        "tlb_store_misses": 0,
        "cache_misses": 0,
        "cache_references": 0,
        "context_switches": global_stats["context_switches"],
        "instructions": global_stats["instructions"],
        "branches": global_stats["branches"],
        "branch_misses": global_stats["branch_misses"],        
    })
    # More metrics
    cache_miss_rate = (
        stats["cache_misses"] / stats["cache_references"]
        if stats["cache_references"] > 0 else 0
    )
    branch_miss_rate = (
        stats["branch_misses"] / stats["branches"]
        if stats["branches"] > 0 else 0
    )
    access_frequency = (
        stats["tlb_load_misses"] + stats["tlb_store_misses"] + 
        stats["cache_misses"] + stats["cache_references"]
    )

    # All pages that are mod 10 create a page fault
    label = 1 if page % 10 == 0 else 0

    # Append the data
    data.append({
        "page": page,
        "page_faults": stats["page_faults"],
        "tlb_load_misses": stats["tlb_load_misses"],
        "tlb_store_misses": stats["tlb_store_misses"],
        "cache_misses": stats["cache_misses"],
        "cache_references": stats["cache_references"],
        "cache_miss_rate": cache_miss_rate,
        "access_frequency": access_frequency,
        "context_switches": stats["context_switches"],
        "instructions": stats["instructions"],
        "branches": stats["branches"],
        "branch_misses": stats["branch_misses"],
        "branch_miss_rate": branch_miss_rate,
        "label": label
    })

df = pd.DataFrame(data)
print(df.head())
df.to_csv("ml_dataset.csv", index=False)


"""
perf record -e page-faults,dTLB-load-misses,dTLB-store-misses,cache-references,cache-misses,context-switches,instructions,branches,branch-misses ./your_workload

sudo perf record -e page-faults,dTLB-load-misses,dTLB-store-misses,cache-references,cache-misses,context-switches,instructions,branches,branch-misses python3 workload10.py
"""