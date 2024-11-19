#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <time.h>

// Function to parse the size in GiBs from command-line argument
size_t parse_size(const char *str) {
    double size;
    char unit;
    if (sscanf(str, "%lf%c", &size, &unit) != 2) {
        fprintf(stderr, "Invalid size format. Use number followed by 'G', e.g., 4G\n");
        exit(EXIT_FAILURE);
    }
    if (unit != 'G' && unit != 'g') {
        fprintf(stderr, "Unsupported unit '%c'. Only 'G' (GiB) is supported.\n", unit);
        exit(EXIT_FAILURE);
    }
    return (size_t)(size * 1024 * 1024 * 1024);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <size_in_GiB>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    size_t size = parse_size(argv[1]);
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size == -1) {
        perror("sysconf");
        exit(EXIT_FAILURE);
    }

    printf("System page size: %ld bytes\n", page_size);
    printf("Mapping %zu GiB of memory...\n", size / (1024 * 1024 * 1024));

    void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    printf("Memory mapped at address: %p\n", addr);

    if (madvise(addr, size, MADV_NOHUGEPAGE) != 0) {
        perror("madvise");
    }

    printf("MADV_NOHUGEPAGE applied to the mapped memory.\n");

    size_t num_pages = size / page_size;
    printf("Total pages to touch: %zu\n", num_pages);

    FILE *log_file = fopen("page_access_log.csv", "w");
    if (!log_file) {
        perror("fopen");
        munmap(addr, size);
        exit(EXIT_FAILURE);
    }

    fprintf(log_file, "Page_Number,Page_Address,Access_Time_ns,Access_Type\n");

    // Initial touch
    for (size_t i = 0; i < num_pages; i++) {
        uintptr_t current_addr = (uintptr_t)addr + i * page_size;
        volatile uint32_t *ptr = (volatile uint32_t *)current_addr;

        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t access_time = (uint64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;

        *ptr = 0;

        fprintf(log_file, "%zu,0x%lx,%llu,WRITE\n", i, current_addr, (unsigned long long)access_time);
    }

    printf("Successfully touched all pages and logged access information.\n");

    // Continuous access loop
    printf("Starting continuous memory access for data collection...\n");
    for (int t = 0; t < 60; t++) { // Run for 60 seconds
        for (size_t i = 0; i < num_pages; i++) {
            uintptr_t current_addr = (uintptr_t)addr + i * page_size;
            volatile uint32_t *ptr = (volatile uint32_t *)current_addr;
            *ptr += 1; // Perform a simple write operation
        }
        usleep(1000000); // Sleep for 100ms between iterations
    }

    printf("Completed continuous memory access.\n");

    fclose(log_file);

    if (munmap(addr, size) == -1) {
        perror("munmap");
        exit(EXIT_FAILURE);
    }

    printf("Memory unmapped successfully. Exiting.\n");
    return 0;
}
