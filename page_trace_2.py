from bcc import BPF
import pandas as pd
import time
import threading
import subprocess
import ctypes
import numpy as np

bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>

struct data_t {
    u64 page_id;
    u64 fault_time_ns;
    u64 fault_type;     // Read or write fault
    u64 fault_distance; // Distance from last fault (in pages)
};

BPF_PERF_OUTPUT(events);

// Track fault statistics
BPF_HASH(fault_count_per_page, u64, u64);    // How many times each page faulted
BPF_HASH(last_fault_time, u64, u64);         // Last fault time per page
BPF_HASH(last_fault_page, u64, u64);         // Last page that faulted
BPF_HASH(sequential_faults, u64, u64);       // Count of sequential faults per page

int kprobe__handle_pte_fault(struct pt_regs *ctx, struct vm_area_struct *vma,
                            unsigned long address, unsigned int flags) {
    u64 page_id = address / 4096;
    u64 timestamp = bpf_ktime_get_ns();
    
    // Update fault count for this page
    u64 *count = fault_count_per_page.lookup(&page_id);
    if (count) {
        (*count)++;
    } else {
        u64 initial = 1;
        fault_count_per_page.update(&page_id, &initial);
    }

    // Calculate distance from last fault
    u64 fault_distance = 0;
    u64 zero = 0;
    u64 *last_page = last_fault_page.lookup(&zero);
    if (last_page) {
        if (*last_page > page_id) {
            fault_distance = *last_page - page_id;
        } else {
            fault_distance = page_id - *last_page;
        }
    }
    last_fault_page.update(&zero, &page_id);

    // Check if this is a sequential fault
    if (fault_distance == 1) {
        u64 *seq = sequential_faults.lookup(&page_id);
        if (seq) {
            (*seq)++;
        } else {
            u64 initial = 1;
            sequential_faults.update(&page_id, &initial);
        }
    }

    // Emit event
    struct data_t data = {};
    data.page_id = page_id;
    data.fault_time_ns = timestamp;
    data.fault_type = (vma->vm_flags & 0x2) ? 1 : 0;  // 1 for write, 0 for read
    data.fault_distance = fault_distance;
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_program)

# Define columns for fault analysis
columns = [
    'page_id',
    'fault_count',
    'fault_type',
    'fault_distance',
    'time_since_last_fault_ns',
    'is_sequential',
    'is_expected_fault'  # From workload pattern
]
df = pd.DataFrame(columns=columns)

last_fault_dict = {}

def handle_event(cpu, data, size):
    event = b["events"].event(data)
    page_id = event.page_id
    fault_time = event.fault_time_ns
    
    key = ctypes.c_ulonglong(page_id)
    
    # Get fault count for this page
    try:
        fault_count = b["fault_count_per_page"][key].value
    except KeyError:
        fault_count = 1
    
    # Calculate time since last fault
    time_since_last_fault = 0
    if page_id in last_fault_dict:
        time_since_last_fault = fault_time - last_fault_dict[page_id]
    last_fault_dict[page_id] = fault_time
    
    # Check if this is a sequential fault
    try:
        sequential_count = b["sequential_faults"][key].value
        is_sequential = 1
    except KeyError:
        is_sequential = 0
    
    # Determine if this is an expected fault (every 10th page)
    is_expected_fault = 1 if (page_id % 10 == 0) else 0
    
    # Add to DataFrame
    df.loc[len(df)] = [
        page_id,
        fault_count,
        event.fault_type,
        event.fault_distance,
        time_since_last_fault,
        is_sequential,
        is_expected_fault
    ]

# Set up event handling
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

# Save raw data
df.to_csv('page_fault_2.csv', index=False)

# Perform statistical analysis
print("\nPage Fault Statistics:")
print("----------------------")
print(f"Total faults recorded: {len(df)}")
print(f"Unique pages that faulted: {len(df['page_id'].unique())}")
print(f"Percentage of expected faults: {(df['is_expected_fault'].sum() / len(df)) * 100:.2f}%")
print(f"Average distance between faults: {df['fault_distance'].mean():.2f} pages")
print("\nFault type distribution:")
print(df['fault_type'].value_counts(normalize=True).multiply(100))

print("\nTiming analysis:")
print(f"Mean time between faults: {df['time_since_last_fault_ns'].mean() / 1e6:.2f} ms")
print(f"Median time between faults: {df['time_since_last_fault_ns'].median() / 1e6:.2f} ms")

print("\nSequential vs Random faults:")
print(f"Sequential faults: {df['is_sequential'].sum()}")
print(f"Random faults: {len(df) - df['is_sequential'].sum()}")

# Correlation analysis
correlations = df.corr()
print("\nFeature correlations:")
print(correlations['fault_count'].sort_values(ascending=False))

print("\nDataset in 'page_fault_2.csv'")