import mmap
import os
import time
import ctypes
import psutil
import csv

PAGE_SIZE = 4096    # 4 KB
NUM_PAGES = 1000    # Number of pages for dataset
ARRAY_SIZE = PAGE_SIZE * NUM_PAGES
DATA_FILE = 'page_fault_data.csv'

def get_mmap_address(mem_map):
    return ctypes.addressof(ctypes.c_char.from_buffer(mem_map))

def collect_system_metrics():
    """
    Collects relevant system metrics using psutil.
    """
    process = psutil.Process(os.getpid())
    cpu_percent = psutil.cpu_percent(interval=None)
    memory_info = process.memory_info()
    rss = memory_info.rss      # Resident Set Size
    vms = memory_info.vms      # Virtual Memory Size
    # You can add more metrics as needed
    return {
        'cpu_percent': cpu_percent,
        'rss': rss,
        'vms': vms
    }

def main():
    pid = os.getpid()
    print(f'Process PID: {pid}')

    # Initialize CSV file with headers
    with open(DATA_FILE, 'w', newline='') as csvfile:
        fieldnames = ['access_index', 'cpu_percent', 'rss', 'vms', 'page_fault']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

    # Delay to allow any monitoring tools to start
    print("Starting workload in 5 seconds...")
    time.sleep(5)

    # Create a temporary file to back mmap
    filename = "temp_mmap"
    with open(filename, "wb") as f:
        f.truncate(ARRAY_SIZE)

    # Open the file and create a memory map
    with open(filename, "r+b") as f:
        mem_map = mmap.mmap(f.fileno(), ARRAY_SIZE, access=mmap.ACCESS_WRITE)
        
        try:
            base_addr = get_mmap_address(mem_map)
            print(f"Starting memory operations at base address: 0x{base_addr:x}")
            
            print("Beginning page access pattern...")
            
            # Access each page and collect data
            for i in range(NUM_PAGES):
                offset = i * PAGE_SIZE
                absolute_addr = base_addr + offset

                # Determine if this access will cause a page fault
                page_fault = 1 if i % 10 == 0 else 0

                # Collect system metrics before access
                metrics = collect_system_metrics()

                # Write to page to potentially create a page fault
                mem_map[offset:offset + PAGE_SIZE] = b"\xFF" * PAGE_SIZE
                print(f'Accessed page {i} at address 0x{absolute_addr:x} - Page Fault: {page_fault}')

                # Record data
                data = {
                    'access_index': i,
                    'cpu_percent': metrics['cpu_percent'],
                    'rss': metrics['rss'],
                    'vms': metrics['vms'],
                    'page_fault': page_fault
                }
                with open(DATA_FILE, 'a', newline='') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=['access_index', 'cpu_percent', 'rss', 'vms', 'page_fault'])
                    writer.writerow(data)

                # Sleep to simulate workload
                time.sleep(0.01)
                
        finally:
            mem_map.close()

    # Clean up temporary file
    os.remove(filename)
    print(f'Data collection complete. Data saved to {DATA_FILE}')

if __name__ == "__main__":
    main()
