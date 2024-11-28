import re
from collections import defaultdict
import pandas as pd

PAGE_SIZE = 4096    # 4KB
NUM_PAGES = 1000    # Num pages in workload

def parse_perf_data(perf_file, mmap_info_file):
    # Read mmap base address
    base_addr = None
    with open(mmap_info_file, 'r') as f:
        for line in f:
            if 'Base Address:' in line:
                base_addr = int(line.split(': ')[1].strip(), 16)
                break
    
    if base_addr is None:
        raise ValueError("Could not find base address in mmap_info.txt")

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

    # Compile regex patterns
    addr_pattern = re.compile(r":\s+\d+\s+\S+:\s+([0-9a-fA-F]+)")
    event_pattern = re.compile(r"\s+(\d+)\s+(\w[\w-]+)")

    with open(perf_file, 'r') as f:
        for line in f:
            addr_match = addr_pattern.search(line)
            event_match = event_pattern.search(line)
            
            if addr_match and event_match:
                addr = int(addr_match.group(1), 16)
                count = int(event_match.group(1))
                event_type = event_match.group(2)
                
                # Calculate page number relative to base address
                if addr >= base_addr and addr < base_addr + (PAGE_SIZE * NUM_PAGES):
                    page_num = (addr - base_addr) // PAGE_SIZE
                    if event_type in page_stats[page_num]:
                        page_stats[page_num][event_type] += count

    # Convert to DataFrame
    df = pd.DataFrame.from_dict(page_stats, orient='index')
    df.index.name = 'page_number'
    return df

# Usage
df = parse_perf_data('perf_output.txt', 'mmap_info.txt')
df.to_csv('memory_access_stats.csv')