import mmap
import os
import time
import ctypes
import random

PAGE_SIZE = 4096    # 4 KB
NUM_PAGES = 5000    # Num of pages for dataset
ARRAY_SIZE = PAGE_SIZE * NUM_PAGES

def get_mmap_address(mem_map):
    return ctypes.addressof(ctypes.c_char.from_buffer(mem_map))

def main():
    pid = os.getpid()
    print(f'Process PID: {pid}')

    print("Starting workload in 5 seconds...")
    time.sleep(5)
    
    filename = "temp_mmap"
    with open(filename, "wb") as f:
        f.truncate(ARRAY_SIZE)

    with open(filename, "r+b") as f:
        mem_map = mmap.mmap(f.fileno(), ARRAY_SIZE, access=mmap.ACCESS_WRITE)
        
        try:
            base_addr = get_mmap_address(mem_map)
            print(f"Starting memory operations at base address: 0x{base_addr:x}")
            print("Beginning varied page access pattern...")
            
            i = 0
            while i < NUM_PAGES:
                # Random burst of accesses
                if random.random() < 0.3:
                    burst_size = random.randint(2, 5)
                    for _ in range(burst_size):
                        if i >= NUM_PAGES:
                            break
                        offset = i * PAGE_SIZE
                        absolute_addr = base_addr + offset
                        mem_map[offset:offset + PAGE_SIZE] = b"\xFF" * PAGE_SIZE
                        print(f'Burst accessed page {i} at address 0x{absolute_addr:x}')
                        time.sleep(0.001)
                        i += 1
                    # Longer pause after burst
                    time.sleep(random.uniform(0.02, 0.05))
                
                # Regular access with varied delays
                else:
                    offset = i * PAGE_SIZE
                    absolute_addr = base_addr + offset
                    mem_map[offset:offset + PAGE_SIZE] = b"\xFF" * PAGE_SIZE
                    print(f'Regular accessed page {i} at address 0x{absolute_addr:x}')
                    
                    # Random delay between accesses
                    if random.random() < 0.2:
                        time.sleep(0.01)
                    else:
                        time.sleep(0.015)
                    i += 1

        finally:
            mem_map.close()

    os.remove(filename)

if __name__ == "__main__":
    main()