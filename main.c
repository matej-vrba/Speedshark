#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>
#include <signal.h>
#include <arpa/inet.h>


#include "util.h"
#include "shb.h"
#include "idb.h"
#include "pb.h"
#include "file.h"
#include "filter.h"

FILE* jq_file = NULL;
filter_t filter;

void fup_handler(int signal) {
	switch (signal) {
	case SIGSEGV:
		fprintf(stderr, "Caught fault (SIGSEGV)\n");
		break;
	case SIGBUS:
		fprintf(stderr, "Caught fault (SIGBUS)\n");
		break;
	case SIGILL:
		fprintf(stderr, "Caught fault (SIGILL)\n");
		break;
	default:
		raise(signal);
	}
	// for SIGSEGV and SIGBUS print a dump
	dump();
	raise(signal);
}


int32_t identify_block(file_t *f, file_t* outfile){
    switch(((int32_t*)f->data)[0]){
        case 0xa0d0d0a:
            return parse_shb(f, outfile);
        case 0x00000001:
            return parse_idb(f, outfile);
        case 0x00000006:
             return parse_pb(f, outfile);
             return 0;
        default:
            printf("=> Unknown header 0x%08x\n", ((int32_t*)f->data)[0]);
            break;
    }

    return -1;
}


int little_endian = 1;
int header_num = 1;
// I can't be bothered not making it global
int unknown_fd = 0;
//#include <time.h>

int main(int argc, char *argv[]) {
    signal(SIGSEGV, fup_handler);
    signal(SIGBUS, fup_handler);
    signal(SIGILL, fup_handler);

    load_filters();
    //srand(time(NULL));
    char* orig_data_pos;
    uint64_t input_file_size = 0;


    if (argc != 3){
        fprintf(stderr, "Expecing two arguments - input and output file\n");
        return 255;
    }


    file_t f __attribute__ ((__cleanup__(close_file))) = open_infile(argv[1]);
    if(f.data == NULL){
        return 1;
    }
    orig_data_pos = f.data;
    input_file_size = f.sb.st_size;

    file_t outfile __attribute__ ((__cleanup__(close_file))) = open_outfile(argv[2], f.sb.st_size);
    if(outfile.data == NULL){
        return 1;
    }

    unknown_fd = open("unknown.pcapng", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (unknown_fd == -1) {
        perror( "Error opening unknown.pcapng");
        goto exit_failure;
    }
    //hexdump(f.data, 200);

    jinit();

    //printf("file size: %lu\n", input_file_size);
    int32_t len = identify_block(&f, &outfile);
    assert(len > 0);
    f.data += len;
    input_file_size -= len;

    len = identify_block(&f, &outfile);
    assert(len > 0);
    f.data += len;
    input_file_size -= len;

    jprintf("[{}");
    len = identify_block(&f, &outfile);
    assert(len > 0);
    f.data += len;
    input_file_size -= len;
    while (input_file_size > 0){
        jnew_row();
        len = identify_block(&f, &outfile);
        assert(len > 0);
        f.data += len;
        input_file_size -= len;
        //printf("\n");
    }
    jprintf("]\n");
    if(input_file_size <= 0){
        //printf("Finished processintg %s\n", argv[1]);
    }





    f.data = orig_data_pos;
    return EXIT_SUCCESS;
    exit_failure:
    return 2;
}
