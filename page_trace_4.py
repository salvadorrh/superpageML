from bcc import BPF
import pandas as pd
import time
import threading
import subprocess
import ctypes

bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>

struct fault_data_t {
    u64 page_id;           // Which page faulted
    u64 timestamp_ns;      // When the fault occurred
    u64 is_write;          // Was it a write fault?
    u64 distance;          // Distance from last fault (in pages)
    u32 pid;              // Process ID that caused the fault
};

BPF_PERF_OUTPUT(events);
BPF_HASH(last_fault_page, u32, u64);  // Track last page that faulted per process

int kprobe__handle_mm_fault(struct pt_regs *ctx, struct vm_area_struct *vma,
                            unsigned long address, unsigned int flags) {
    struct fault_data_t data = {};
    
    data.page_id = address / 4096;  // Convert to page number
    data.timestamp_ns = bpf_ktime_get_ns();
    data.is_write = !!(vma->vm_flags & 0x2);  // Check VM_WRITE flag
    data.pid = bpf_get_current_pid_tgid() >> 32;
    
    // Calculate distance from last fault
    u64 *last_page = last_fault_page.lookup(&data.pid);
    if (last_page) {
        data.distance = data.page_id - *last_page;
    }
    
    // Update last fault page
    last_fault_page.update(&data.pid, &data.page_id);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_program)

# Store fault data
fault_data = []

def handle_event(cpu, data, size):
    event = b["events"].event(data)
    fault_data.append({
        'page_id': event.page_id,
        'timestamp_ns': event.timestamp_ns,
        'is_write': event.is_write,
        'distance': event.distance,
        'pid': event.pid
    })

b["events"].open_perf_buffer(handle_event)

def poll_events():
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

# Start polling thread
thread = threading.Thread(target=poll_events)
thread.daemon = True
thread.start()

print("Setting up BPF...")
time.sleep(5)

print('Starting workload:')
subprocess.run(["python3", "workload10.py"])

time.sleep(5)

# Create DataFrame
df = pd.DataFrame(fault_data)

if len(df) > 0:
    # Add derived features
    df['time_since_last_fault'] = df['timestamp_ns'].diff()
    df['is_10th_page'] = (df['page_id'] % 10 == 0).astype(int)
    
    # Save dataset
    df.to_csv('only_pfs.csv', index=False)
    
    print("\nPage Fault Analysis:")
    print(f"Total faults captured: {len(df)}")
    print(f"Number of 10th page faults: {df['is_10th_page'].sum()}")
    print(f"Average distance between faults: {df['distance'].mean():.2f} pages")
    print(f"Average time between faults: {df['time_since_last_fault'].mean()/1e6:.2f} ms")
    
    print("\nFeature Statistics:")
    print(df.describe())
else:
    print("No faults collected")