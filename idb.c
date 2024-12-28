#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "idb.h"
#include "file.h"
#include "util.h"


extern int unknown_fd;
#define printf(...)
#define hexdump(...)

int32_t parse_idb(file_t *f, file_t* outfile){
    //int64_t section_len;
    int32_t block_len;

    printf("=> IDB\n");
    printf("first type: 0x%08x\n", ((int32_t*)f->data)[0]);
    block_len = ((int32_t*)f->data)[1];
    printf("len: %d\n", block_len);
    switch(((int16_t*)(f->data + 8))[0]){
        case 0x0001:
            printf("Ethernet (0x%04x)\n", ((int16_t*)(f->data + 8))[0]);
            break;
            default:
            printf("unknown link type 0x%04x\n", ((int16_t*)(f->data + 8))[0]);
    }



    hexdump((uint8_t*)f->data, block_len);
    memcpy(outfile->data, f->data, block_len);
    outfile->data += block_len;
    //write(outfile, f->data, block_len);
    write(unknown_fd, f->data, block_len);
    return block_len;
    //return block_len;
}
