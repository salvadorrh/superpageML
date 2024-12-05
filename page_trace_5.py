from bcc import BPF
import pandas as pd
import time
import threading
import subprocess
import ctypes
import os

# Store the workload PID globally
WORKLOAD_PID = 0

def get_workload_pid(proc):
    global WORKLOAD_PID
    WORKLOAD_PID = proc.pid
    print(f"Workload PID: {WORKLOAD_PID}")

bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>

// Define a kernel space variable to hold our PID
BPF_HASH(target_pid, u32, u32, 1);

struct fault_data_t {
    u64 page_id;           
    u64 timestamp_ns;      
    u64 is_write;         
    u64 distance;         
    u32 pid;              
    u32 fault_flags;      
    u64 vm_flags;         
    u64 fault_count;      
    u64 vma_start;        
    u64 vma_end;          
};

BPF_PERF_OUTPUT(events);
BPF_HASH(last_fault_page, u32, u64);    
BPF_HASH(page_fault_count, u64, u64);   
BPF_HASH(process_fault_count, u32, u64); 

int kprobe__handle_mm_fault(struct pt_regs *ctx, struct vm_area_struct *vma,
                            unsigned long address, unsigned int flags) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Look up our target PID
    u32 key = 0;
    u32 *workload_pid = target_pid.lookup(&key);
    if (!workload_pid || pid != *workload_pid) {
        return 0;
    }
    
    if (!(flags & FAULT_FLAG_WRITE)) {
    return 0;
    }

    struct fault_data_t data = {};
    
    data.page_id = address / 4096;
    data.timestamp_ns = bpf_ktime_get_ns();
    data.is_write = !!(vma->vm_flags & 0x2);
    data.pid = pid;
    data.fault_flags = flags;
    data.vm_flags = vma->vm_flags;
    data.vma_start = vma->vm_start;
    data.vma_end = vma->vm_end;
    
    // Calculate distance from last fault
    u64 *last_page = last_fault_page.lookup(&pid);
    if (last_page) {
        data.distance = data.page_id - *last_page;
    }
    last_fault_page.update(&pid, &data.page_id);
    
    // Update fault count for this page
    u64 *count = page_fault_count.lookup(&data.page_id);
    if (count) {
        (*count)++;
    } else {
        u64 initial = 1;
        page_fault_count.update(&data.page_id, &initial);
    }
    data.fault_count = count ? *count : 1;
    
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
        'pid': event.pid,
        'fault_flags': event.fault_flags,
        'vm_flags': event.vm_flags,
        'fault_count': event.fault_count,
        'vma_start': event.vma_start,
        'vma_end': event.vma_end
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

print('Starting workload...')
workload_process = subprocess.Popen(["python3", "workload10.py"])
get_workload_pid(workload_process)

# Update the PID in kernel space
pid_key = ctypes.c_uint(0)
pid_value = ctypes.c_uint(WORKLOAD_PID)
b["target_pid"][pid_key] = pid_value

print(f"Tracking page faults for PID: {WORKLOAD_PID}")

# Wait for workload to complete
workload_process.wait()
time.sleep(1)  # Give time for last events

# Create DataFrame
df = pd.DataFrame(fault_data)

if len(df) > 0:
    print(f"\nCollected {len(df)} page faults")
    print(f"Expected around (1000 pages / 10)")
    print("\nUnique PIDs in data:")
    print("\nUnique fault flags seen:")
    print(df['fault_flags'].unique())
    print(df['pid'].value_counts())
    
    if len(df) > 0:
        df['time_since_last_fault'] = df['timestamp_ns'].diff()
        df['is_10th_page'] = (df['page_id'] % 10 == 0).astype(int)
        df['offset_in_vma'] = df['page_id']*4096 - df['vma_start']
        df['vma_size'] = df['vma_end'] - df['vma_start']
        df['relative_position'] = df['offset_in_vma'] / df['vma_size']
        df['sequential_access'] = (df['distance'] == 1).astype(int)
        
        df.to_csv('only_pfs.csv', index=False)
        print("\nFeature Statistics:")
        print(df.describe())
else:
    print("No faults collected")