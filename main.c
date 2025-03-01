#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>
#include <signal.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <time.h>

               

#include "util.h"
#include "shb.h"
#include "idb.h"
#include "pb.h"
#include "file.h"
#include "filter.h"

FILE* jq_file = NULL;
FILE* csv_file = NULL;
filter_t filter;

int first_sig = 1;

void fup_handler(int sig) {
  // only handle each signal once
    signal(sig, SIG_DFL);
  switch (sig) {
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
		raise(sig);
	}
	// for SIGSEGV and SIGBUS print a dump
	dump();
	raise(sig);
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
    time_t start;
    start = time(NULL);



    load_filters();
    //srand(time(NULL));
    char* orig_data_pos;
    uint64_t input_file_size = 0;


    if (argc != 3){
        fprintf(stderr, "Expecing two arguments - input and output file\n");
        fprintf(stderr, "Possible environemnt variables:\n");
        fprintf(stderr, "SSHARK_SRC_IP\n");
        fprintf(stderr, "SSHARK_DST_IP\n");
        fprintf(stderr, "SSHARK_IP_ADD\n");
        fprintf(stderr, "SSHARK_SRC_PORT\n");
        fprintf(stderr, "SSHARK_DST_PORT\n");
        fprintf(stderr, "SSHARK_PORT\n");
        fprintf(stderr, "SSHARK_JSON_FILE\n");
        fprintf(stderr, "SSHARK_CSV_FILE\n");
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
    csvinit();

    //const uint8_t str[] = "";
    //csvprint(str);

    //csvprint("");
    __csvprint_coma();
    csvprint("type");
    csvprint("time_relative");
    csvprint("tstamp");
    csvprint("vlan_id");
    csvprint("mac_src");
    csvprint("mac_dst");
    csvprint("ip_ihl");
    csvprint("ip_tos");
    csvprint("ip_src");
    csvprint("ip_dst");
    csvprint("tcp_seq");
    csvprint("tcp_ack");
    csvprint("sport");
    csvprint("dport");
    csvprint("flags");
    csvprint("trans_len");
    csvprint("enip_sess");
    csvprint("enip_fields");
    csvprint("cid");
    csvprint("cip_seq");
    csvprint("cip_service");
    csvprint("cip_service_path");
    csvnewline();

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
        csvnewline();
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
    csvnewline();




    fprintf(stderr, "Processed %d packets in %lds\n", header_num, time(NULL) - start);

    f.data = orig_data_pos;
    return EXIT_SUCCESS;
    exit_failure:
    return 2;
}
