/*
 * memory_bugs.c
 * Intentionally vulnerable C code for static analysis training
 * Contains: Buffer Overflow, Use-After-Free, Double Free, OOB Read
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/memory_bugs.h"

/* CWE-121: Stack-based Buffer Overflow */
void vuln_stack_overflow(const char *user_input) {
    char buf[64];
    // BUG: strcpy has no bounds checking — input > 64 bytes overflows stack
    strcpy(buf, user_input);
    printf("Received: %s\n", buf);
}

/* CWE-122: Heap-based Buffer Overflow */
char *vuln_heap_overflow(int size) {
    char *buf = (char *)malloc(size);
    if (!buf) return NULL;
    // BUG: memset writes 256 bytes regardless of allocation size
    memset(buf, 'A', 256);
    return buf;
}

/* CWE-416: Use-After-Free */
void vuln_use_after_free(void) {
    int *ptr = (int *)malloc(sizeof(int));
    if (!ptr) return;
    *ptr = 42;
    free(ptr);
    // BUG: ptr is accessed after being freed
    printf("Value: %d\n", *ptr);
}

/* CWE-415: Double Free */
void vuln_double_free(int condition) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    strcpy(buf, "sensitive_data");
    if (condition) {
        free(buf);
    }
    // BUG: buf is always freed here, but may have already been freed above
    free(buf);
}

/* CWE-125: Out-of-Bounds Read */
int vuln_oob_read(int index) {
    int arr[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    // BUG: index is not validated — attacker controls read offset
    return arr[index];
}

/* CWE-787: Out-of-Bounds Write */
void vuln_oob_write(int index, int value) {
    int arr[10];
    // BUG: no bounds check — arbitrary memory write primitive
    arr[index] = value;
}

/* CWE-401: Memory Leak */
void vuln_memory_leak(int count) {
    for (int i = 0; i < count; i++) {
        char *buf = (char *)malloc(1024);
        if (!buf) return;
        sprintf(buf, "item_%d", i);
        // BUG: buf is never freed — heap exhaustion possible
    }
}

/* CWE-690: NULL Pointer Dereference after malloc */
void vuln_null_deref(void) {
    int *ptr = (int *)malloc(sizeof(int));
    // BUG: return value of malloc not checked before use
    *ptr = 100;
    free(ptr);
}
