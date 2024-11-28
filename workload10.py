import mmap
import os
import time
import ctypes

PAGE_SIZE = 4096    # 4 KB
NUM_PAGES = 1000    # Num of pages for dataset
ARRAY_SIZE = PAGE_SIZE * NUM_PAGES  # Size of mem to be mmapped

def get_mmap_address(mem_map):
    return ctypes.addressof(ctypes.c_char.from_buffer(mem_map))

def main():
    pid = os.getpid()
    base_addr = None
    
    # Create a temp file to back mmap
    filename = "temp_mmap"
    with open(filename, "wb") as f:
        f.truncate(ARRAY_SIZE)

    # Open file and create a mem map
    with open(filename, "r+b") as f:
        mem_map = mmap.mmap(f.fileno(), ARRAY_SIZE, access=mmap.ACCESS_WRITE)
        
        try:
            # Get and save the base address
            base_addr = get_mmap_address(mem_map)
            with open("mmap_info.txt", "w") as info_file:
                info_file.write(f"PID: {pid}\n")
                info_file.write(f"Base Address: 0x{base_addr:x}\n")
                info_file.write(f"Page Size: {PAGE_SIZE}\n")
                info_file.write(f"Number of Pages: {NUM_PAGES}\n")
            
            # Access pages and log addresses
            with open("access_log.txt", "w") as log_file:
                for i in range(0, NUM_PAGES, 10):
                    offset = i * PAGE_SIZE
                    absolute_addr = base_addr + offset
                    mem_map[offset:offset + PAGE_SIZE] = b"\x00" * PAGE_SIZE
                    log_file.write(f"Page {i}: Offset 0x{offset:x}, Address 0x{absolute_addr:x}\n")
                    time.sleep(0.01)
                    
        finally:
            mem_map.close()

    os.remove(filename)

if __name__ == "__main__":
    main()