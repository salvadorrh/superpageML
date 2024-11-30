from bcc import BPF
import pandas as pd
import time
import threading

bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>

// Structure for events
struct data_t {
    u64 page_id;
    u64 access_time_ns;
    u64 access_type; // 0 for read, 1 for write
};

// Define perf output
BPF_PERF_OUTPUT(events);

// Hash maps for access frequency, last access time, read/write counts
BPF_HASH(page_access_freq, u64, u64);
BPF_HASH(page_last_access, u64, u64);
BPF_HASH(page_read_count, u64, u64);
BPF_HASH(page_write_count, u64, u64);

// Kprobe for handle_mm_fault (memory access)
int kprobe__handle_mm_fault(struct pt_regs *ctx, struct vm_area_struct *vma,
                            unsigned long address, unsigned int flags) {
    u64 page_id = address / 4096; // Assuming 4KB pages
    u64 timestamp = bpf_ktime_get_ns();
    
    // Update access frequency
    u64 *freq = page_access_freq.lookup(&page_id);
    if (freq) {
        (*freq)++;
    } else {
        u64 initial = 1;
        page_access_freq.update(&page_id, &initial);
    }
    
    // Update last access time
    page_last_access.update(&page_id, &timestamp);
    
    // Update read/write counts based on flags
    u64 *read_cnt = page_read_count.lookup(&page_id);
    u64 *write_cnt = page_write_count.lookup(&page_id);
    if (flags & FAULT_FLAG_WRITE) { // Assuming FAULT_FLAG_WRITE is defined appropriately
        if (write_cnt) {
            (*write_cnt)++;
        } else {
            u64 initial = 1;
            page_write_count.update(&page_id, &initial);
        }
    } else {
        if (read_cnt) {
            (*read_cnt)++;
        } else {
            u64 initial = 1;
            page_read_count.update(&page_id, &initial);
        }
    }
    
    // Emit event
    struct data_t data = {};
    data.page_id = page_id;
    data.access_time_ns = timestamp;
    data.access_type = (flags & FAULT_FLAG_WRITE) ? 1 : 0;
    events.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}
"""

# Initialize bpf
b = BPF(text = bpf_program)

columns = []
df = pd.DataFrame(columns=columns)

# Start a thread to read BFS maps
thread = threading.Thread()