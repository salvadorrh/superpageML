#!/bin/bash

# Clear any old data
rm -f perf.data perf_output.txt mmap_info.txt

# Start perf recording
sudo perf record -e 'page-faults:u,dTLB-load-misses:u,dTLB-store-misses:u,cache-references:u,cache-misses:u' \
     -a --call-graph dwarf python3 workload10.py

# Generate the perf script output
sudo perf script > perf_output.txt

# Run the parser
python3 parser.py