import mmap
import os
import time
import ctypes

PAGE_SIZE = 4096    # 4 KB
NUM_PAGES = 1000    # Num of pages for dataset
ARRAY_SIZE = PAGE_SIZE * NUM_PAGES

def get_mmap_address(mem_map):
    return ctypes.addressof(ctypes.c_char.from_buffer(mem_map))

def main():
    pid = os.getpid()
    print(f'Process PID: {pid}')
    
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
            
            with open("mmap_info.txt", "w") as info_file:
                info_file.write(f"PID: {pid}\n")
                info_file.write(f"Base Address: 0x{base_addr:x}\n")
                info_file.write(f"Page Size: {PAGE_SIZE}\n")
                info_file.write(f"Number of Pages: {NUM_PAGES}\n")
            
            # Force a sync to ensure file is written
            info_file.flush()
            os.fsync(info_file.fileno())
            
            # Wait a moment for perf to start capturing
            time.sleep(1)
            
            print("Beginning page access pattern...")
            
            # Access every 10th page with more intensive operations
            for i in range(0, NUM_PAGES, 10):
                offset = i * PAGE_SIZE
                absolute_addr = base_addr + offset
                
                # Write operation
                mem_map[offset:offset + PAGE_SIZE] = b"\xFF" * PAGE_SIZE
                
                # Read back to force cache activity
                data = mem_map[offset:offset + PAGE_SIZE]
                
                # Do some simple computation to ensure the access isn't optimized away
                checksum = sum(data)
                
                print(f'Page {i}: addr=0x{absolute_addr:x}, checksum={checksum}')
                time.sleep(0.05)  # Slightly longer delay to ensure perf captures the event
                
        finally:
            mem_map.close()

    os.remove(filename)

if __name__ == "__main__":
    main()