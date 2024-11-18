# collect_page_data.py

from bcc import BPF
import csv
import time

# Define eBPF program
prog = """
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>

// Structure to hold page access data
struct page_access {
    u64 pid;
    u64 tid;
    u64 addr;
    u32 access_type; // 0: Read, 1: Write
    u64 timestamp;
};

// BPF hash map to store page access counts
BPF_HASH(page_access_map, u64, struct page_access);

// kprobe to track page accesses
int kprobe_handle_mm_fault(struct pt_regs *ctx, struct mm_struct *mm, unsigned long address, unsigned int flags, unsigned int type) {
    u64 pid_tid = bpf_get_current_pid_tgid();
    
    struct page_access pa = {};
    pa.pid = pid_tid >> 32;
    pa.tid = pid_tid;
    pa.addr = address;
    pa.access_type = (type & VM_WRITE) ? 1 : 0; // Determine write or read
    pa.timestamp = bpf_ktime_get_ns();
    
    page_access_map.update(&pid_tid, &pa);
    
    return 0;
}

// kretprobe to clean up
int kretprobe_handle_mm_fault(struct pt_regs *ctx) {
    return 0;
}
"""

# Initialize BPF
b = BPF(text=prog)
print("Collecting page access data... Press Ctrl-C to stop.")

# Open CSV file for logging
with open('page_access_log.csv', 'w', newline='') as csvfile:
    fieldnames = ['PID', 'TID', 'Page_Number', 'Address', 'Access_Type', 'Timestamp_ns']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    
    try:
        while True:
            for key, pa in b["page_access_map"].items():
                # Calculate page number (assuming 4 KiB pages and base address)
                base_address = 0x7f9c8b000000  # Replace with your workload's base address
                page_size = 4096
                if pa.addr < base_address:
                    continue
                page_number = (pa.addr - base_address) // page_size
                writer.writerow({
                    'PID': pa.pid,
                    'TID': pa.tid & 0xFFFFFFFF,
                    'Page_Number': page_number,
                    'Address': hex(pa.addr),
                    'Access_Type': 'WRITE' if pa.access_type else 'READ',
                    'Timestamp_ns': pa.timestamp
                })
                # Remove the entry after logging
                b["page_access_map"].delete(key)
            csvfile.flush()
            time.sleep(1)
    except KeyboardInterrupt:
        print("Data collection stopped.")
