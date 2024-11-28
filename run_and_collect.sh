#!/bin/bash

# Clear any old data
rm -f perf.data perf_output.txt mmap_info.txt

# Record with simpler output format
sudo perf stat -x, -o perf_output.txt -e page-faults,dTLB-load-misses,dTLB-store-misses,cache-references,cache-misses -p $(pgrep -f "python3 workload10.py") &
PERF_PID=$!

# Run the workload
python3 workload10.py

# Wait for perf to finish
wait $PERF_PID

# Run the parser
python3 parser.py