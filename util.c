#include "util.h"
#include <stdio.h>
#include <ctype.h>

int jq_first;

void hexdump(const uint8_t *value, size_t len) {
    for (unsigned int i = 0; i < len; ++i) {
        fprintf(stdout, "%.2x ", value[i]);
        if (i % 8 == 7)
            fprintf(stdout, " ");
        if (i % 16 == 15) {
            fprintf(stdout, "   ");
            for (unsigned int j = i - 15; j <= i; ++j) {
                if (isalnum(value[j]))
                    fprintf(stdout, "%c", value[j]);
                else
                    fprintf(stdout, ".");
            }
            fprintf(stdout, "\n");
        }
    }
    // padding for last line, because it's probably shorter than previous line,
    // padding is added so the ascii representation is aligned
    for (unsigned int i = 0; i <= (16 - len % 16) * 3; ++i)
        fprintf(stdout, " ");
    if (len % 16 < 8)
        fprintf(stdout, " ");
    fprintf(stdout, "   ");

    for (unsigned int i = len - (len % 16); i < len; ++i) {
        if (isalnum(value[i]))
            fprintf(stdout, "%c", value[i]);
        else
            fprintf(stdout, ".");
    }
    fprintf(stdout, "\n");
}
