#!/bin/bash

# Start the eBPF data collection in the background
sudo python3 ~/superpage_project/page_metrics_bpf.py &
BPF_PID=$!

# Allow some time for eBPF to initialize
sleep 2

# Run MCF Benchmark (using LMbench as an example)
echo "Running LMbench lat_mem_rd..."
/usr/lib/lmbench/bin/lat_mem_rd 128 1000 > lmbench_output.log

# Run GUPS Benchmark
echo "Running GUPS..."
~/superpage_project/gups/gups -c 1000000000 -t 4 > gups_output.log

# Stop the eBPF data collection
sudo kill $BPF_PID

# Wait for eBPF script to finish saving data
sleep 2

echo "Workloads completed and data collected."
