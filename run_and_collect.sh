# Give it a moment to start
sleep 1

# Record stats for the workload
sudo perf stat -e page-faults,dTLB-load-misses,dTLB-store-misses,cache-references,cache-misses -p $WORKLOAD_PID -o perf_output.txt

# Wait for workload to finish
wait $WORKLOAD_PID

# Fix permissions on output files
sudo chown $USER:$USER perf_output.txt mmap_info.txt

# Run the parser
python3 parser.py