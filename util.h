#ifndef UTIL_H_
#define UTIL_H_
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include "types.h"

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
extern int   jq_first;
extern FILE *jq_file;
extern int   csv_first_col;
extern FILE *csv_file;

typedef struct {
  uint64_t t;
} pcap_time_t;

typedef struct {
  uint8_t addr[6];
} mac_t;

typedef struct {
  uint8_t addr[4];
} ipv4_addr_t;

#define __nop \
  do {        \
  } while (0)

//#define ENABLE_JSON
#ifdef ENABLE_JSON

#  define jinit()                                        \
    do {                                                 \
      if (filter.json_file != NULL) {                    \
        jq_file = fopen(filter.json_file, "w");          \
        if (jq_file == NULL) {                           \
          perror("Failed to open out.json for writing"); \
          jq_file = stdout;                              \
        }                                                \
        jnew_row();                                      \
      }                                                  \
    } while (0)

#  define jprintf(...)                 \
    do {                               \
      if (filter.json_file != NULL) {  \
        fprintf(jq_file, __VA_ARGS__); \
      }                                \
    } while (0)

#  define jnew_row(void)              \
    do {                              \
      if (filter.json_file != NULL) { \
        jq_first = 1;                 \
      }                               \
    } while (0)

#  define jnewline(void)              \
    do {                              \
      if (filter.json_file != NULL) { \
        if (jq_first) {               \
          fprintf(jq_file, ",\n{\n"); \
          jq_first = 0;               \
        } else {                      \
          fprintf(jq_file, ",\n");    \
        }                             \
      }                               \
    } while (0)

#  define jprintu(name, val)                       \
    do {                                           \
      if (filter.json_file != NULL) {              \
        jnewline();                                \
        fprintf(jq_file, "\"%s\": %u", name, val); \
      }                                            \
    } while (0)

#  define jprint_mac(name, mac)              \
    do {                                     \
      if (filter.json_file != NULL) {        \
        jnewline();                          \
        fprintf(jq_file, "\"%s\": ", name);  \
        fprintf(jq_file, "\"");              \
        for (int i = 0; i < 5; i++)          \
          fprintf(jq_file, "%02x:", mac[i]); \
        fprintf(jq_file, "%02x\"", mac[5]);  \
      }                                      \
    } while (0)

#  define jprint_ipv4(name, ip)                                          \
    do {                                                                 \
      if (filter.json_file != NULL) {                                    \
        jnewline();                                                      \
        fprintf(jq_file, "\"%s\": ", name);                              \
        fprintf(jq_file, "\"%d.%d.%d.%d\"", ip[0], ip[1], ip[2], ip[3]); \
      }                                                                  \
    } while (0)

#else //ENABLE_JSON

#  define jinit()
#  define jprintf(...)
#  define jnew_row(void)
#  define jnewline(void)

#  define jprintu(name, val)
#  define jprint_mac(name, mac)
#  define jprint_ipv4(name, ip)
#endif //ENABLE_JSON

#define ENABLE_CSV
#ifdef ENABLE_CSV

#  define csvinit() __csvinit()
#  define csvprint(val)               \
    do {                              \
      __csvprint_coma();              \
      _Generic((val),                 \
        int: __csvprint_u32,          \
        uint8_t: __csvprint_u8,       \
        uint16_t: __csvprint_u16,     \
        int16_t: __csvprint_i16,      \
        uint32_t: __csvprint_u32,     \
        uint64_t: __csvprint_u64,     \
        int64_t: __csvprint_i64,      \
        pcap_time_t: __csvprint_time, \
        mac_t: __csvprint_mac,        \
        ipv4_addr_t: __csvprint_ipv4, \
        char *: __csvprint_str)(val); \
    } while (0)

#  define csvprintnz(val)  \
    do {                   \
      if (val != 0)        \
        csvprint(val);     \
      else                 \
        __csvprint_coma(); \
    } while (0)
#  define csvprintnn(val)  \
    do {                   \
      if (val >= 0)        \
        csvprint(val);     \
      else                 \
        __csvprint_coma(); \
    } while (0)
#  define csvnewline() __csvnewline()

#else //ENABLE_CSV

#  define csvinit() __nop
#  define csvprint(val) __nop
#  define csvprintnz(val) __nop
#  define csvprintnn(val) __nop
#  define csvnewline() __nop

#endif //ENABLE_CSV

void __csvnewline(void);
void __csvinit(void);
void __csvprint_coma(void);
void __csvprint_u8(uint8_t u8);
void __csvprint_u16(uint16_t u16);
void __csvprint_i16(int16_t i16);
void __csvprint_u32(uint32_t u32);
void __csvprint_u64(uint64_t u64);
void __csvprint_i64(int64_t i64);
void __csvprint_str(char *str);
void __csvprint_time(pcap_time_t time);
void __csvprint_mac(mac_t mac);
void __csvprint_ipv4(ipv4_addr_t addr);

extern int  little_endian;
extern void hexdump(const uint8_t *value, size_t len);

pcap_time_t parse_time(uint32_t lower, uint32_t upper);

#endif // UTIL_H_
