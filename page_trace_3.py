from bcc import BPF
import pandas as pd
import time
import threading
import subprocess
import ctypes
import os

# Define page size and shift based on system architecture (typically 4KB pages)
PAGE_SIZE = 4096    # 4 KB
PAGE_SHIFT = 12     # Number of bits to shift for 4 KB pages

# eBPF program to attach to handle_mm_fault and collect comprehensive page fault data
bpf_program = f"""
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>
#include <linux/sched.h>

#define PAGE_SIZE {PAGE_SIZE}
#define PAGE_SHIFT {PAGE_SHIFT}
#define PAGE_MASK (~(PAGE_SIZE - 1))

// Struct to hold fault data
struct data_t {{
    u64 pid;
    u64 tid;
    u64 cpu;
    u64 page_id;
    u64 access_time_ns;
    u32 access_type; // 0: read, 1: write
    u32 fault_type;  // 0: minor, 1: major
    u64 vma_start;
    u64 vma_end;
    u32 vma_flags;
    u64 ip; // Instruction pointer
}};

// Perf buffer for events
BPF_PERF_OUTPUT(events);

// Kprobe for handle_mm_fault (memory access)
int kprobe__handle_mm_fault(struct pt_regs *ctx, struct vm_area_struct *vma,
                            unsigned long address, unsigned int flags) {{
    struct data_t data = {{}};

    // Get PID and TID
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    // Get CPU ID
    data.cpu = bpf_get_smp_processor_id();

    // Align address to page boundary and calculate Page ID
    unsigned long aligned_address = address & PAGE_MASK;
    data.page_id = aligned_address >> PAGE_SHIFT;

    // Get Timestamp
    data.access_time_ns = bpf_ktime_get_ns();

    // Determine Access Type
    data.access_type = (vma->vm_flags & VM_WRITE) ? 1 : 0;

    // Determine Fault Type
    data.fault_type = 1; // Since this is a fault handler

    // VMA Attributes
    data.vma_start = vma->vm_start;
    data.vma_end = vma->vm_end;
    data.vma_flags = vma->vm_flags;

    // Get Instruction Pointer (optional, may add overhead)
    data.ip = PT_REGS_IP(ctx);

    // Submit the event
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}}
"""

# Initialize BPF
b = BPF(text=bpf_program)

# Define DataFrame columns
columns = [
    'pid',
    'tid',
    'cpu',
    'page_id',
    'access_time_ns',
    'access_type',
    'fault_type',
    'vma_start',
    'vma_end',
    'vma_flags',
    'ip',
    'inter_access_time_ns',
    'access_frequency',
    'read_count',
    'write_count',
    'page_fault'
]

# Initialize a list to store records for efficient accumulation
df_records = []

# Dictionaries to track additional features
last_access_dict = {}
access_freq_map = {}
read_count_map = {}
write_count_map = {}

# Event handler function
def handle_event(cpu, data, size):
    event = b["events"].event(data)
    page_id = event.page_id
    access_time_ns = event.access_time_ns
    access_type = event.access_type

    # Update access frequency
    freq = access_freq_map.get(page_id, 0) + 1
    access_freq_map[page_id] = freq

    # Update read/write counts
    if access_type == 0:
        read_cnt = read_count_map.get(page_id, 0) + 1
        read_count_map[page_id] = read_cnt
    else:
        write_cnt = write_count_map.get(page_id, 0) + 1
        write_count_map[page_id] = write_cnt

    # Fetch last access time
    last_time = last_access_dict.get(page_id, access_time_ns)

    # Calculate inter-access time
    inter_access_time_ns = access_time_ns - last_time if page_id in last_access_dict else 0
    last_access_dict[page_id] = access_time_ns

    # Determine if this access causes a fault based on your workload pattern
    # For example, every 10th page access causes a fault
    # Adjust this logic based on your actual workload behavior
    page_fault = 1 if (page_id % 10 == 0 and event.fault_type == 1) else 0

    # Create a record dictionary
    record = {
        'pid': event.pid,
        'tid': event.tid,
        'cpu': event.cpu,
        'page_id': page_id,
        'access_time_ns': access_time_ns,
        'access_type': access_type,
        'fault_type': event.fault_type,
        'vma_start': event.vma_start,
        'vma_end': event.vma_end,
        'vma_flags': event.vma_flags,
        'ip': event.ip,
        'inter_access_time_ns': inter_access_time_ns,
        'access_frequency': freq,
        'read_count': read_count_map.get(page_id, 0),
        'write_count': write_count_map.get(page_id, 0),
        'page_fault': page_fault
    }

    # Append the record to the list
    df_records.append(record)

# Attach event handler
b["events"].open_perf_buffer(handle_event)

# Function to poll events
def poll_events():
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            break

# Start a thread to poll events
thread = threading.Thread(target=poll_events)
thread.daemon = True
thread.start()

# Allow BPF to set up
time.sleep(5)

# Specify your workload script
workload_script = "workload10.py"

# Check if the workload script exists
if not os.path.exists(workload_script):
    print(f"Workload script '{workload_script}' not found. Please ensure it exists in the current directory.")
    exit(1)

# Run the desired workload
print('Starting workload:')
subprocess.run(["python3", workload_script])

# Allow some time for events to be processed after workload completion
time.sleep(5)

# Convert the list of records to a DataFrame
df = pd.DataFrame(df_records, columns=columns)

# Save the collected data to a CSV file
df.to_csv('page_fault_dataset.csv', index=False)
print("Dataset saved to 'page_fault_dataset.csv'")
