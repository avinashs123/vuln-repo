/*
 * logic_bugs.c
 * Intentionally vulnerable C code for static analysis training
 * Contains: Race Conditions (TOCTOU), Incorrect Comparisons, Logic Errors
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "../include/logic_bugs.h"

/* CWE-362: TOCTOU Race Condition (Time-of-Check to Time-of-Use) */
int vuln_toctou_file(const char *filename) {
    // BUG: file is checked for access, then opened — attacker can swap symlink
    // between the access() check and the open() call
    if (access(filename, R_OK) == 0) {
        // Window of vulnerability: attacker replaces filename with symlink here
        int fd = open(filename, O_RDONLY);
        if (fd < 0) return -1;
        char buf[256];
        read(fd, buf, sizeof(buf));
        close(fd);
        return 0;
    }
    return -1;
}

/* CWE-367: TOCTOU with stat + open */
void vuln_toctou_stat(const char *path) {
    struct stat st;
    // BUG: stat result is stale by the time open() runs
    if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
        FILE *fp = fopen(path, "rb");
        if (fp) {
            // process file...
            fclose(fp);
        }
    }
}

/* CWE-253: Incorrect check of function return value */
void vuln_ignored_return(void) {
    char *buf = (char *)malloc(1024);
    // BUG: return value of fgets not checked
    fgets(buf, 1024, stdin);
    // If fgets returns NULL (error/EOF), buf content is undefined
    printf("Input: %s\n", buf);
    free(buf);
}

/* CWE-195: Signed/Unsigned Conversion Error */
void vuln_signed_comparison(int user_len) {
    char buf[256];
    // BUG: user_len is signed; if negative, comparison passes but memcpy wraps
    if (user_len < 256) {
        memcpy(buf, "source_data", user_len);  // negative len = huge copy
    }
}

/* CWE-170: Improper Null Termination */
void vuln_no_null_termination(const char *src, int len) {
    char dst[64];
    // BUG: strncpy does NOT null-terminate if src is >= dst size
    strncpy(dst, src, sizeof(dst));
    // dst may not be null-terminated; printf reads into adjacent memory
    printf("Output: %s\n", dst);
}

/* CWE-457: Use of Uninitialized Variable */
int vuln_uninitialized(int condition) {
    int result;  // BUG: result is never assigned if condition == 0
    if (condition > 0) {
        result = condition * 2;
    }
    return result;  // undefined value returned if condition <= 0
}

/* CWE-476: NULL Pointer Dereference */
void vuln_null_ptr(char *input) {
    char *token = strtok(input, ",");
    // BUG: if strtok returns NULL (no comma found), next strtok is on NULL
    char *second = strtok(NULL, ",");
    // BUG: second might be NULL; strlen(NULL) is undefined behavior
    printf("Second token length: %zu\n", strlen(second));
}
