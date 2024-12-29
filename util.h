#ifndef UTIL_H_
#define UTIL_H_
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Indicates whether this is first element in the json object.
// Json output by speedshark is an array of flat json objects (no nested objects).
// Before first key-value pair in an object is printed, there is either '[{' or '{'
// already printed
// When printing new pair the macro first calls jnewline, which if it's the first
// key-value pair in the object only prints newline, if not prints coma and
// then newline (to add coma after previous pair).
// After that the key-value pair is printed without newline. If another key-value
// pair continues it will call jnewline which will add coma and newline. However
// if it's the last, only a newline and closing bracket '}' is printed (this is in
// main.c). This makes sure that there are not comas after last key-value pair (which
// json doesn't like)
extern int jq_first;
extern FILE *jq_file;

#define ENABLE_JSON
#ifdef ENABLE_JSON

#define jinit()                                                                \
	do {                                                                   \
		if (filter.json_file != NULL) {                                \
			jq_file = fopen(filter.json_file, "w");                      \
			if (jq_file == NULL) {                                 \
				perror("Failed to open out.json for writing"); \
				jq_file = stdout;                              \
			}                                                      \
			jnew_row();                                            \
		}                                                              \
	} while (0)

#define jprintf(...)                                   \
	do {                                           \
		if (filter.json_file != NULL) {        \
			fprintf(jq_file, __VA_ARGS__); \
		}                                      \
	} while (0)

#define jnew_row(void)                          \
	do {                                    \
		if (filter.json_file != NULL) { \
			jq_first = 1;           \
		}                               \
	} while (0)

#define jnewline(void)                                   \
	do {                                             \
		if (filter.json_file != NULL) {          \
			if (jq_first) {                  \
				fprintf(jq_file, ",\n{\n");  \
				jq_first = 0;            \
			} else {                         \
				fprintf(jq_file, ",\n"); \
			}                                \
		}                                        \
	} while (0)

#define jprintu(name, val)                                         \
	do {                                                       \
		if (filter.json_file != NULL) {                    \
			jnewline();                                \
			fprintf(jq_file, "\"%s\": %u", name, val); \
		}                                                  \
	} while (0)

#define jprint_mac(name, mac)                                      \
	do {                                                       \
		if (filter.json_file != NULL) {                    \
			jnewline();                                \
			fprintf(jq_file, "\"%s\": ", name);        \
			fprintf(jq_file, "\"");                    \
			for (int i = 0; i < 5; i++)                \
				fprintf(jq_file, "%02x:", mac[i]); \
			fprintf(jq_file, "%02x\"", mac[5]);        \
		}                                                  \
	} while (0)

#define jprint_ipv4(name, ip)                                             \
	do {                                                              \
		if (filter.json_file != NULL) {                           \
			jnewline();                                       \
			fprintf(jq_file, "\"%s\": ", name);               \
			fprintf(jq_file, "\"%d.%d.%d.%d\"", ip[0], ip[1], \
				ip[2], ip[3]);                            \
		}                                                         \
	} while (0)

#else //ENABLE_JSON

#define jinit()
#define jprintf(...)
#define jnew_row(void)
#define jnewline(void)

#define jprintu(name, val)
#define jprint_mac(name, mac)
#define jprint_ipv4(name, ip)
#endif //ENABLE_JSON

extern int little_endian;
extern void hexdump(const uint8_t *value, size_t len);

#endif // UTIL_H_
