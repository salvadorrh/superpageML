import re
from collections import defaultdict

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

"""
perf record -e page-faults,dTLB-load-misses,dTLB-store-misses,cache-references,cache-misses,context-switches,instructions,branches,branch-misses ./your_workload
"""