#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>



#include "shb.h"
#include "file.h"
#include "util.h"


extern int unknown_fd;

#define printf(...)
#define hexdump(...)

int32_t parse_shb(file_t* f, file_t* outfile){
    int64_t section_len;
    int32_t block_len;

    printf("first type: 0x%x\n", ((int32_t*)f->data)[0]);
    block_len = ((int32_t*)f->data)[1];
    printf("block len: %d (0x%08x)\n", block_len, block_len);
    printf("byte order: 0x%x", ((int32_t*)f->data)[2]);
    if(((int32_t*)f->data)[2] == 0x1a2b3c4d){
        little_endian = 0;
    }else{
        fprintf(stderr, "This endianness was not tested\n");
        return -2;
    }
    if(little_endian)
        printf(" (little endian)\n");
    else
        printf(" (big endian)\n");
    printf("version: %d.%d\n", ((int16_t*)(f->data + 12))[0], ((int16_t*)(f->data + 12))[1]);
    section_len = ((int64_t*)(f->data + 16))[0];
    assert(section_len == -1); //if this fails, it needs to be taken care about when writing new header
    printf("section len: 0x%lx (%ld)\n", section_len, section_len);
    char* data = f->data;

    printf("options: \n");
    hexdump((uint8_t*)data, block_len);
    memcpy(outfile->data, data, block_len);
    outfile->data += block_len;
    //write(outfile, data, block_len);
    write(unknown_fd, data, block_len);
    return block_len;
}
