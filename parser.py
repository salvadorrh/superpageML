import re
from collections import defaultdict
import pandas as pd

PAGE_SIZE = 4096
NUM_PAGES = 1000

def parse_perf_data(perf_file, mmap_info_file):
    # Read mmap base address
    base_addr = None
    with open(mmap_info_file, 'r') as f:
        for line in f:
            if 'Base Address:' in line:
                base_addr = int(line.split(': ')[1].strip(), 16)
                print(f"Found base address: 0x{base_addr:x}")
                break
    
    if base_addr is None:
        raise ValueError("Could not find base address in mmap_info.txt")

    page_stats = defaultdict(lambda: {
        "page_faults": 0,
        "tlb_load_misses": 0,
        "tlb_store_misses": 0,
        "cache_misses": 0,
        "cache_references": 0
    })

    # Updated regex pattern to match the new format
    # Example: "python3 16435 10966.398011:          1      page-faults:u:      7fda3ea48290"
    event_pattern = re.compile(r':\s+(\d+)\s+([\w-]+):u:\s+([0-9a-fA-F]+)')

    print("Starting to parse perf output...")
    line_count = 0
    match_count = 0
    kernel_addr_count = 0
    user_addr_count = 0
    
    with open(perf_file, 'r') as f:
        for line in f:
            line_count += 1
            if line_count <= 5:
                print(f"Sample line {line_count}: {line.strip()}")
            
            match = event_pattern.search(line)
            
            if match:
                count = int(match.group(1))
                event_type = match.group(2)
                addr = int(match.group(3), 16)
                
                # Skip kernel addresses
                if addr > 0xffffffff00000000:
                    kernel_addr_count += 1
                    continue
                
                user_addr_count += 1
                match_count += 1
                
                if line_count <= 5:
                    print(f"Found match: addr=0x{addr:x}, count={count}, event={event_type}")
                
                # Calculate page number relative to base address
                if addr >= base_addr and addr < base_addr + (PAGE_SIZE * NUM_PAGES):
                    page_num = (addr - base_addr) // PAGE_SIZE
                    # Convert event type to match our dictionary keys
                    event_key = event_type.lower().replace('-', '_')
                    if event_key in page_stats[page_num]:
                        page_stats[page_num][event_key] += count
                        if line_count <= 5:
                            print(f"Added event to page {page_num}")

    print(f"\nProcessing summary:")
    print(f"Total lines processed: {line_count}")
    print(f"Total matches found: {match_count}")
    print(f"Kernel addresses found: {kernel_addr_count}")
    print(f"User addresses found: {user_addr_count}")
    print(f"Number of pages with data: {len(page_stats)}")

    # Convert to DataFrame
    df = pd.DataFrame.from_dict(page_stats, orient='index')
    df.index.name = 'page_number'
    
    # Fill NaN values with 0
    df = df.fillna(0)
    
    print("\nDataFrame head:")
    print(df.head())
    return df

# Usage
print("Starting parser...")
df = parse_perf_data('perf_output.txt', 'mmap_info.txt')
df.to_csv('memory_access_stats.csv')