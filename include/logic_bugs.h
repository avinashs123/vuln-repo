#ifndef LOGIC_BUGS_H
#define LOGIC_BUGS_H

int  vuln_toctou_file(const char *filename);
void vuln_toctou_stat(const char *path);
void vuln_ignored_return(void);
void vuln_signed_comparison(int user_len);
void vuln_no_null_termination(const char *src, int len);
int  vuln_uninitialized(int condition);
void vuln_null_ptr(char *input);

#endif
