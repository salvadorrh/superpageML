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

columns = ['page_id', 'access_frequency', 'last_access_time_ns', 'read_count', 'write_count', 'inter_access_time_ns', 'access_type', 'page_fault']
df = pd.DataFrame(columns=columns)

last_access_dict = {}

# Event handler
def handle_event(cpu, data, size):
    event = b["events"].event(data)
    page_id = event.page_id
    access_time_ns = event.access_time_ns
    access_type = event.access_type
    
    # Fetch access frequency
    freq = 0
    try:
        freq = b["page_access_freq"][page_id].value
    except KeyError:
        freq = 1
    
    # Fetch last access time
    try:
        last_time = b["page_last_access"][page_id].value
    except KeyError:
        last_time = access_time_ns
    
    # Fetch read/write counts
    read_cnt = 0
    write_cnt = 0
    try:
        read_cnt = b["page_read_count"][page_id].value
    except KeyError:
        read_cnt = 0
    try:
        write_cnt = b["page_write_count"][page_id].value
    except KeyError:
        write_cnt = 0
    
    # Calculate inter access time
    inter_access_time_ns = 0
    if page_id in last_access_dict:
        inter_access_time_ns = access_time_ns - last_access_dict[page_id]
    last_access_dict[page_id] = access_time_ns
    
    # Assuming every 10th page access causes a page fault
    page_fault = 1 if (page_id % 10 == 0) else 0
    
    # Append to DataFrame
    df.loc[len(df)] = [page_id, freq, last_time, read_cnt, write_cnt, inter_access_time_ns, access_type, page_fault]

# Attach event handler
b["events"].open_perf_buffer(handle_event)

def poll_events():
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()


# Start a thread to read BFS maps
thread = threading.Thread(target=poll_events)
thread.daemon = True
thread.start()

# Allow some time for BPF to set up
time.sleep(10)

# Now run the desired workload
import subprocess
print('Starting workload:')
subprocess.run(["python3", "workload10.py"])

# Allos some time for events to be processed
time.sleep(10)
df.to_csv('page_fault_dataset.csv', index=False)
print("Dataset saved to 'page_fault_dataset.csv'")
