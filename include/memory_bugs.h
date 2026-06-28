#ifndef MEMORY_BUGS_H
#define MEMORY_BUGS_H

void vuln_stack_overflow(const char *user_input);
char *vuln_heap_overflow(int size);
void vuln_use_after_free(void);
void vuln_double_free(int condition);
int  vuln_oob_read(int index);
void vuln_oob_write(int index, int value);
void vuln_memory_leak(int count);
void vuln_null_deref(void);

#endif
