#ifndef FORMAT_INJECTION_H
#define FORMAT_INJECTION_H

void vuln_format_string(const char *user_input);
void vuln_fprintf_format(const char *filename, const char *user_msg);
void vuln_command_injection(const char *filename);
void vuln_popen_injection(const char *host);
void vuln_path_traversal(const char *user_file);
void vuln_integer_overflow(unsigned int width, unsigned int height);
int  vuln_integer_underflow(unsigned int user_len);

#endif
