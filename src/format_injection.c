/*
 * format_injection.c
 * Intentionally vulnerable C code for static analysis training
 * Contains: Format String bugs, Command Injection, Path Traversal
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../include/format_injection.h"

/* CWE-134: Uncontrolled Format String */
void vuln_format_string(const char *user_input) {
    // BUG: user_input passed directly as format string
    // Attacker can use %x %s %n to read/write arbitrary memory
    printf(user_input);
}

/* CWE-134: Format string via fprintf */
void vuln_fprintf_format(const char *filename, const char *user_msg) {
    FILE *fp = fopen(filename, "a");
    if (!fp) return;
    // BUG: same class of bug via fprintf
    fprintf(fp, user_msg);
    fclose(fp);
}

/* CWE-78: OS Command Injection */
void vuln_command_injection(const char *filename) {
    char cmd[256];
    // BUG: filename is embedded into shell command without sanitization
    // Attacker supplies: "file.txt; rm -rf /" or "file.txt && cat /etc/passwd"
    snprintf(cmd, sizeof(cmd), "cat /var/log/%s", filename);
    system(cmd);
}

/* CWE-78: Command injection via popen */
void vuln_popen_injection(const char *host) {
    char cmd[512];
    // BUG: host is not validated; injected with semicolons/pipes
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", host);
    FILE *fp = popen(cmd, "r");
    if (fp) pclose(fp);
}

/* CWE-22: Path Traversal */
void vuln_path_traversal(const char *user_file) {
    char path[512];
    // BUG: user_file can contain "../../../etc/passwd"
    snprintf(path, sizeof(path), "/var/app/uploads/%s", user_file);
    FILE *fp = fopen(path, "r");
    if (!fp) return;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        printf("%s", line);
    }
    fclose(fp);
}

/* CWE-190: Integer Overflow leading to heap overflow */
void vuln_integer_overflow(unsigned int width, unsigned int height) {
    // BUG: width * height can overflow before malloc, allocating tiny buffer
    // then the subsequent write overflows the heap
    unsigned int size = width * height * 4;
    char *buf = (char *)malloc(size);
    if (!buf) return;
    memset(buf, 0, width * height * 4); // overflows if size wrapped
    free(buf);
}

/* CWE-191: Integer Underflow */
int vuln_integer_underflow(unsigned int user_len) {
    unsigned int safe_len = user_len - 1; // BUG: if user_len == 0, wraps to UINT_MAX
    char *buf = (char *)malloc(safe_len);
    if (!buf) return -1;
    free(buf);
    return (int)safe_len;
}
