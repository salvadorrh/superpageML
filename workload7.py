import mmap
import os
import time
import ctypes

PAGE_SIZE = 4096    # 4 KB
NUM_PAGES = 5000    # Num of pages for dataset
ARRAY_SIZE = PAGE_SIZE * NUM_PAGES

def get_mmap_address(mem_map):
    return ctypes.addressof(ctypes.c_char.from_buffer(mem_map))

def main():
    pid = os.getpid()
    print(f'Process PID: {pid}')

    # Delay to have time to run the eBPF script
    print("Starting workload in 5 seconds...")
    time.sleep(5)
    
    # Create a temp file to back mmap
    filename = "temp_mmap"
    with open(filename, "wb") as f:
        f.truncate(ARRAY_SIZE)

    # Open file and create a mem map
    with open(filename, "r+b") as f:
        mem_map = mmap.mmap(f.fileno(), ARRAY_SIZE, access=mmap.ACCESS_WRITE)
        
        try:
            base_addr = get_mmap_address(mem_map)
            print(f"Starting memory operations at base address: 0x{base_addr:x}")
            print("Beginning page access pattern...")
            
            # Access every 10th page
            for i in range(0, NUM_PAGES):
                if i % 5 == 0:
                    offset = i * PAGE_SIZE
                    absolute_addr = base_addr + offset
                    
                    # Write to page to create fault
                    mem_map[offset:offset + PAGE_SIZE] = b"\xFF" * PAGE_SIZE
                    print(f'Accessed page {i} at address 0x{absolute_addr:x}')
                    time.sleep(0.01)
                if i % 4 == 0:
                    offset = i * PAGE_SIZE
                    absolute_addr = base_addr + offset
                    
                    # Write to page to create fault
                    mem_map[offset:offset + PAGE_SIZE] = b"\xFF" * PAGE_SIZE
                    print(f'Accessed page {i} at address 0x{absolute_addr:x}')
                    time.sleep(0.03)
                if i % 7 == 0:
                    time.sleep(0.02)

        finally:
            mem_map.close()

    os.remove(filename)

if __name__ == "__main__":
    main()