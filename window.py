from bcc import BPF
import time
import subprocess
import threading
from collections import defaultdict
import pandas as pd

# Configuration
WINDOW_SIZE = '250ms'  # Adjust this value as needed ('100ms', '250ms', '500ms', etc.)
PREDICTION_HORIZON = 1  # Number of windows to look ahead for labeling

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u64 ts;
    u32 pid;
    u64 minor_faults;
    u64 major_faults;
};

BPF_PERF_OUTPUT(page_faults);

TRACEPOINT_PROBE(mm, mm_page_fault_user) {
    struct data_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.minor_faults = 1;
    page_faults.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(mm, mm_page_fault) {
    struct data_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.major_faults = 1;
    page_faults.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_text)

# Data storage
data_records = []

# Event handler
def handle_event(cpu, data, size):
    event = b["page_faults"].event(data)
    timestamp = event.ts / 1e9  # Convert ns to seconds
    data_records.append({
        'timestamp': timestamp,
        'pid': event.pid,
        'minor_faults': event.minor_faults,
        'major_faults': event.major_faults
    })

# Register event handler
b["page_faults"].open_perf_buffer(handle_event)

# Function to poll BPF events
def run_bpf():
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

# Start BPF polling in a separate thread
bpf_thread = threading.Thread(target=run_bpf)
bpf_thread.start()

# Run the workload
subprocess.run(["python3", "workload10.py"])

# Allow some time for BPF to finish
time.sleep(2)

# Stop the BPF thread
bpf_thread.join(timeout=1)

# Convert to DataFrame
df = pd.DataFrame(data_records)

# Check if DataFrame is not empty
if df.empty:
    print("No data collected.")
    exit()

# Set timestamp as index
df.set_index('timestamp', inplace=True)

# Resample into configurable windows
windowed = df.resample(WINDOW_SIZE).sum().fillna(0)

# Create labels based on prediction horizon
windowed['label'] = (windowed['minor_faults'].shift(-PREDICTION_HORIZON) +
                     windowed['major_faults'].shift(-PREDICTION_HORIZON)).apply(lambda x: 1 if x > 0 else 0)

# Drop the last 'prediction_horizon' rows with NaN labels
windowed = windowed.iloc[:-PREDICTION_HORIZON]

# Feature engineering (example)
windowed['minor_faults_avg'] = windowed['minor_faults'].rolling(window=5).mean().fillna(0)
windowed['major_faults_avg'] = windowed['major_faults'].rolling(window=5).mean().fillna(0)

# Save dataset
windowed.to_csv('page_fault_dataset.csv', index=True)
print("Dataset saved to 'page_fault_dataset.csv'")
