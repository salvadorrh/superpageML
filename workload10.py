import mmap
import os
import time

PAGE_SIZE = 4096    # 4 KB
NUM_PAGES = 1000    # Num of pages for dataset
ARRAY_SIZE = PAGE_SIZE * NUM_PAGES  # Size of mem to be mmapped

# Create a temp file to back mmap
filename = "temp_mmap"
with open(filename, "wb") as f:
    f.truncate(ARRAY_SIZE)  # Required size

# Open file and create a mem map
with open(filename, "r+b") as f:
    mem_map = mmap.mmap(f.fileno(), ARRAY_SIZE, access = mmap.ACCESS_WRITE)

    try:
        # Access pages
        for i in range(0, NUM_PAGES, 10):
            offset = i * PAGE_SIZE
            mem_map[offset:offset + PAGE_SIZE] = b"\x00" * PAGE_SIZE # Write to the specific are that we want
            print(f'Accessed page {i} at offset {offset}')
            time.sleep(0.01)
    finally:
        mem_map.close()

os.remove(filename)