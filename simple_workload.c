#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

size_t parse_size(const char *str) {
    double size;
    char unit;
    // 4G
    if (sscanf(str, "%lf%c", &size, &unit) != 2) {
        fprintf(stderr, "Use something like 4G\n");
        exit(EXIT_FAILURE);
    }
    // Convert GiBs to bytes
    return (size_t)(size * 1024 * 1024 * 1024);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <size_in_GiB>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    size_t size = parse_size(argv[1]); // Num of bytes

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

    // not use superpage
    if (madvise(addr, size, MADV_NOHUGEPAGE) != 0) {
        perror("madvise");
        exit(EXIT_FAILURE);
    }

    // Number of pages to touch
    size_t num_pages = size / page_size;
    printf("Total pages to touch: %zu\n", num_pages);

    // Iterate over each page and touch the first word
    for (size_t i = 0; i < num_pages; i++) {
        uintptr_t current_addr = (uintptr_t)addr + i * page_size;
        volatile uint32_t *ptr = (volatile uint32_t *)current_addr; // Write to mem
        *ptr = 0;  // Touch the page by writting to first word
    }

    printf("Successfully touched all pages.\n");

    // Unmap the memory before exiting
    if (munmap(addr, size) == -1) {
        perror("munmap");
        exit(EXIT_FAILURE);
    }

    printf("Memory unmapped successfully. Exiting.\n");

    return 0;
}