# page_metrics_bpf.py
from bcc import BPF
import pandas as pd
import time

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>

struct data_t {
    u64 addr;
    u32 event_type; // 1: Access, 2: TLB Miss
};
BPF_PERF_OUTPUT(events);

int trace_page_access(struct pt_regs *ctx, struct mm_struct *mm, unsigned long address, unsigned int flags, unsigned int trap) {
    struct data_t data = {};
    data.addr = address & PAGE_MASK;
    data.event_type = 1; // Access
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_tlb_miss(struct pt_regs *ctx, struct mm_struct *mm, unsigned long address, unsigned int flags, unsigned int trap) {
    struct data_t data = {};
    data.addr = address & PAGE_MASK;
    data.event_type = 2; // TLB Miss
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_text)

# Attach kprobes to relevant kernel functions
# Note: Replace 'handle_mm_fault' and 'tlb_miss_handler' with actual function names
# You may need to identify the correct kernel functions handling TLB misses
b.attach_kprobe(event="handle_mm_fault", fn_name="trace_page_access")
b.attach_kprobe(event="do_page_fault", fn_name="trace_tlb_miss")  # Example

# Data storage
page_metrics = {}

# Event handler
def handle_event(cpu, data, size):
    event = b["events"].event(data)
    page = event.addr
    if page not in page_metrics:
        page_metrics[page] = {'access_count': 0, 'tlb_misses': 0}
    if event.event_type == 1:
        page_metrics[page]['access_count'] += 1
    elif event.event_type == 2:
        page_metrics[page]['tlb_misses'] += 1

# Start data collection
b["events"].open_perf_buffer(handle_event)
print("Starting data collection... Press Ctrl+C to stop.")

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nData collection stopped.")

# Save collected data to CSV
data = []
for addr, metrics in page_metrics.items():
    data.append({
        'Page_Address': hex(addr),
        'Access_Count': metrics['access_count'],
        'TLB_Miss_Count': metrics['tlb_misses']
    })

df = pd.DataFrame(data)
df.to_csv('page_metrics.csv', index=False)
print("Data saved to page_metrics.csv")
