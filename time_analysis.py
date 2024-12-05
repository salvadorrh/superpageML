from bcc import BPF
import pandas as pd
import time
import threading
import subprocess
import ctypes
from collections import defaultdict

bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>

struct data_t {
    u64 timestamp;           // When the fault occurred
    u64 page_id;            // Page that faulted
    u64 fault_type;         // Read or write fault
    u32 pid;                // Process ID
    u32 memory_pressure;    // Current memory pressure indicator
};

BPF_PERF_OUTPUT(events);

// Track system-wide memory stats
BPF_HASH(fault_count_window, u64, u64);  // Faults per time window
BPF_HASH(last_fault_time, u64, u64);     // Last fault time
BPF_HASH(process_fault_count, u32, u64); // Faults per process
BPF_HASH(total_faults, u64, u64);        // Total fault counter

int kprobe__handle_pte_fault(struct pt_regs *ctx, struct vm_area_struct *vma,
                            unsigned long address, unsigned int flags) {
    u64 timestamp = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 pid64 = (u64)pid;  // Convert pid to u64
    
    // Calculate current time window (1ms windows)
    u64 window = timestamp / 1000000;
    
    // Update fault count for current window
    u64 *count = fault_count_window.lookup(&window);
    if (count) {
        (*count)++;
    } else {
        u64 initial = 1;
        fault_count_window.update(&window, &initial);
    }
    
    // Update process fault count
    u64 *proc_count = process_fault_count.lookup(&pid);
    if (proc_count) {
        (*proc_count)++;
    } else {
        u64 initial = 1;
        process_fault_count.update(&pid, &initial);
    }
    
    // Update last fault time using pid64
    last_fault_time.update(&pid64, &timestamp);
    
    // Update total faults (for memory pressure approximation)
    u64 zero = 0;
    u64 *total = total_faults.lookup(&zero);
    if (total) {
        (*total)++;
    } else {
        u64 initial = 1;
        total_faults.update(&zero, &initial);
    }
    
    struct data_t data = {};
    data.timestamp = timestamp;
    data.page_id = address / 4096;
    data.fault_type = (vma->vm_flags & 0x2) ? 1 : 0;
    data.pid = pid;
    
    // Get current total faults as a simple memory pressure indicator
    total = total_faults.lookup(&zero);
    data.memory_pressure = total ? (*total & 0xFFFFFFFF) : 0;  // Convert to u32
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""


WINDOW_SIZE_MS = 10  # 10ms windows
HISTORY_WINDOWS = 5   # Look at last 5 windows for prediction

class WindowTracker:
    def __init__(self):
        self.windows = defaultdict(int)  # {window_id: fault_count}
        self.current_window = 0
        self.window_features = []
        self.labels = []
        self.lock = threading.Lock()  # Add lock for synchronization
        self.processing_complete = False
    
    def update(self, timestamp_ns):
        with self.lock:
            window_id = timestamp_ns // (WINDOW_SIZE_MS * 10000)
            
            if window_id > self.current_window:
                # Create feature vector for previous window
                if self.current_window > 0:
                    features = self._create_features(self.current_window)
                    if features is not None:
                        next_window_faults = self.windows[self.current_window + 1]
                        self.window_features.append(features)
                        self.labels.append(1 if next_window_faults > 0 else 0)
                
                self.current_window = window_id
    
    def add_fault(self, timestamp_ns):
        with self.lock:
            window_id = timestamp_ns // (WINDOW_SIZE_MS * 1000000)
            self.windows[window_id] += 1
    
    def _create_features(self, window_id):
        if window_id <= HISTORY_WINDOWS:
            return None
            
        features = {
            'faults_current': self.windows[window_id],
            'total_faults_history': sum(self.windows[window_id - i] for i in range(1, HISTORY_WINDOWS + 1)),
            'max_faults_history': max(self.windows[window_id - i] for i in range(1, HISTORY_WINDOWS + 1)),
            'min_faults_history': min(self.windows[window_id - i] for i in range(1, HISTORY_WINDOWS + 1)),
            'trend': sum((i + 1) * self.windows[window_id - i] for i in range(HISTORY_WINDOWS)) / HISTORY_WINDOWS,
            'window_id': window_id
        }
        return features
    
    def complete_processing(self):
        """Mark processing as complete and handle the last window"""
        with self.lock:
            self.processing_complete = True
            # Process the last window if needed
            if self.current_window > 0:
                features = self._create_features(self.current_window)
                if features is not None:
                    next_window_faults = self.windows[self.current_window + 1]
                    self.window_features.append(features)
                    self.labels.append(1 if next_window_faults > 0 else 0)
    
    def get_dataset(self):
        """Get aligned features and labels"""
        with self.lock:
            if len(self.window_features) > len(self.labels):
                self.window_features = self.window_features[:len(self.labels)]
            elif len(self.labels) > len(self.window_features):
                self.labels = self.labels[:len(self.window_features)]
                
            return self.window_features.copy(), self.labels.copy()  # Return copies to be thread-safe

# Initialize BPF
b = BPF(text=bpf_program)

# Initialize window tracker
tracker = WindowTracker()

def handle_event(cpu, data, size):
    event = b["events"].event(data)
    if not tracker.processing_complete:
        tracker.update(event.timestamp)
        tracker.add_fault(event.timestamp)

b["events"].open_perf_buffer(handle_event)

def poll_events():
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            tracker.complete_processing()
            exit()

# Start polling thread
thread = threading.Thread(target=poll_events)
thread.daemon = True
thread.start()

print("Setting up BPF...")
time.sleep(5)

print('Starting workload:')
subprocess.run(["python3", "workload10.py"])

# Make sure all processing is complete
time.sleep(1)
tracker.complete_processing()

print("\nCollecting dataset...")
features, labels = tracker.get_dataset()

print(f"Features collected: {len(features)}")
print(f"Labels collected: {len(labels)}")

if len(features) != len(labels):
    print("WARNING: Features and labels lengths don't match!")
    min_len = min(len(features), len(labels))
    features = features[:min_len]
    labels = labels[:min_len]
    print(f"Truncated both to length: {min_len}")

if len(features) > 0:
    df = pd.DataFrame(features)
    df['next_window_has_fault'] = labels
    
    # Save dataset
    df.to_csv('time_window_fault_data.csv', index=False)
    
    # Print analysis
    print("\nTime Window Analysis:")
    print(f"Total windows analyzed: {len(df)}")
    print(f"Windows with faults: {len(df[df['faults_current'] > 0])}")
    print(f"Prediction windows with faults: {sum(labels)}")
    
    print("\nFeature Statistics:")
    print(df.describe())
    
    print("\nCorrelations with fault occurrence:")
    correlations = df.corr()['next_window_has_fault'].sort_values(ascending=False)
    print(correlations)
    
    print("\nDataset saved to 'time_window_fault_data.csv'")
else:
    print("No windows collected. Try adjusting the WINDOW_SIZE_MS or running the workload longer.")
