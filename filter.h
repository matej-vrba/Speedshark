#ifndef FILTER_H_
#define FILTER_H_
#include <stdint.h>

typedef struct{
    uint8_t src_ip[4];
    uint32_t *src_ip32;
    uint8_t dst_ip[4];
    uint32_t *dst_ip32;
    uint8_t ip_add[4];
    uint32_t *ip_add32;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t port;
    char* json_file;
    char* csv_file;
}filter_t;
extern filter_t filter;

void load_filters(void);

#endif // FILTER_H_
