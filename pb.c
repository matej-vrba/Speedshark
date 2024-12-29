#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>



#include "pb.h"
#include "file.h"
#include "util.h"
#include "filter.h"

#define FILTER_DROP -1
#define FILTER_ACCEPT -2
#define FILTER_HDR_NOT_FOUND -3

#define MAX_PACKETS 64
uint8_t* header_ptrs[MAX_PACKETS];
int headers;
int header_types[MAX_PACKETS];
typedef enum {
    TYPE_ETH2,
    TYPE_VLAN,
    TYPE_IPv4,
    TYPE_TCP,
    TYPE_UDP,
    TYPE_IO_ENIP,
    TYPE_EX_ENIP,
    TYPE_TL,
    TYPE_CIP,

} TypeID;

extern int header_num;
extern int unknown_fd;

#pragma pack(push, 1)
typedef struct {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t next_header;
} ether2_t;
typedef struct {
    uint16_t vlan_id;
    uint16_t next_header;
} vlan_t;
typedef struct {
    uint8_t ver : 4;
    uint8_t len : 4;
    uint8_t dscp;
    uint16_t full_len;
    uint16_t id;
    uint16_t frag_and_flags;
    uint8_t ttl;
    uint8_t next_header;
    uint16_t checksum;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
} ipv4_t;
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint16_t flags_len;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
} tcp_t;
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
} udp_t;
typedef struct {
    uint16_t num_items;
    uint16_t type1;
    uint16_t len;
    uint32_t cid;
    uint32_t seq;
    uint16_t type2;
    uint16_t len2;
} io_enip_t;
typedef struct {
    uint16_t cmd;
    uint16_t len;
    uint32_t session;
    uint32_t status;
    uint64_t context;
    uint32_t opts;
    uint32_t int_handle;
    uint16_t timeout;
    uint16_t num_items;
} expl_enip_t;
typedef struct {
    uint16_t type;
    uint16_t len;
} tl_t;
// This won't be another rant, but can someone please explain why they used 1b
// type and length for path, but 2b for type and length in command specific data
typedef struct {
    uint8_t type;
    uint8_t len;
} tl1b_t;
typedef struct {
    uint8_t service;
    uint8_t path_len;
} cip_t;
#pragma pack(pop)

static size_t l4len;


#define ASSERT(x) do{if(!(x)) {dump(); assert(0);}}while(0)

#define PARSE_START(type) type *hdr = ((type*)data);
#define NEXT_HEADER(type)\
    return chose_next_header(data + sizeof(type), len - sizeof(type), hdr->next_header);

#define indent(void)                                                               \
    printf("%.*s", (i + indent_adjust) * 2, "               XXX");
#define iprintf(fmt, ...)                                                               \
    printf("%.*s" fmt,  (i + indent_adjust) * 2, "               XXX", __VA_ARGS__);

#define DUMP_PREP(type)\
            len = sizeof(type);\
            data = header_ptrs[i];\
            PARSE_START(type);

static void print_mac(uint8_t mac[6]){
    for(int i =0; i < 5; i++)
        printf("%02x:", mac[i]);
    printf("%02x\n", mac[5]);
}

void dump(void){
    uint8_t *data;
    size_t len;
    int32_t indent_adjust = 0;
    printf("========================\n");
    printf("Filter dump of %d layers\n", headers);
    printf("========================\n");
    printf("header num: %d\n", header_num - 1);
    for (int i =0; i < headers; i++){
        if (header_types[i]== TYPE_ETH2){
            DUMP_PREP(ether2_t);
            indent();
            printf("dst_mac: ");
            print_mac(hdr->dst_mac);
            indent();
            printf("src_mac: ");
            print_mac(hdr->src_mac);
            iprintf("next header: 0x%04x\n", hdr->next_header);
        } else if (header_types[i]== TYPE_VLAN){
            DUMP_PREP(vlan_t);
            iprintf("vlan id: %d\n", hdr->vlan_id);
            iprintf("next header: 0x%04x\n", hdr->next_header);
        } else if (header_types[i]== TYPE_IPv4){
            DUMP_PREP(ipv4_t);
            iprintf("length: %d\n", hdr->full_len);
            iprintf("frag_offset: %d\n", (hdr->frag_and_flags  & 31));// 31 - 0b11111
            iprintf("flags: 0x%02x\n", hdr->frag_and_flags >> 5 );
            iprintf("dst_ip: %d.%d.%d.%d\n", hdr->dst_ip[0], hdr->dst_ip[1], hdr->dst_ip[2], hdr->dst_ip[3]);
            iprintf("src_ip: %d.%d.%d.%d\n", hdr->src_ip[0], hdr->src_ip[1], hdr->src_ip[2], hdr->src_ip[3]);
            iprintf("next header: 0x%04x\n", hdr->next_header);
        } else if (header_types[i]== TYPE_TCP){
            DUMP_PREP(tcp_t);
            iprintf("dst port: %d\n", ntohs(hdr->dst_port));
            iprintf("src port: %d\n", ntohs(hdr->src_port));
            iprintf("seq: %d\n", ntohl(hdr->seq));
            iprintf("ack: %d\n", ntohl(hdr->ack));
        } else if (header_types[i]== TYPE_UDP){
            DUMP_PREP(udp_t);
            iprintf("dst port: %d\n", ntohs(hdr->dst_port));
            iprintf("src port: %d\n", ntohs(hdr->src_port));
        } else if (header_types[i]== TYPE_IO_ENIP){
            DUMP_PREP(io_enip_t);
            indent();
            printf("=> IO_ENIP\n");
            iprintf("len: %d\n", hdr->len);
            iprintf("cid: 0x%08x\n", hdr->len);
        } else if (header_types[i]== TYPE_EX_ENIP){
            DUMP_PREP(expl_enip_t);
            indent();
            printf("=> EX_ENIP\n");
            iprintf("cmd: 0x%08x\n", hdr->cmd);
            iprintf("session: 0x%08x\n", hdr->session);
            iprintf("status: 0x%08x\n", hdr->status);
            iprintf("context: 0x%016lx\n", hdr->context);
            iprintf("options: 0x%08x\n", hdr->opts);
            iprintf("len: %d\n", hdr->len);
            iprintf("num_items: %d\n", hdr->num_items);
        } else if (header_types[i]== TYPE_TL){
            DUMP_PREP(tl_t);
            indent_adjust--;
            indent();
            printf("=> TLV\n");
            iprintf("type: 0x%04x\n", hdr->type);
            iprintf("type: 0x%04x\n", hdr->len);
            indent();
            printf("data:\n");
            hexdump(data + len, hdr->len);
            //TODO cip
        } else{
            printf("dump print function not implemented for type 0x%x\n", header_types[i]);
            assert(0);
        }
    }
}


static int32_t chose_next_header(uint8_t *data, size_t len, uint16_t nh);

static int32_t parse_ipv4(uint8_t *data, size_t len){
    header_ptrs[headers] = data;
    header_types[headers] =  TYPE_IPv4;
    headers++;

    PARSE_START(ipv4_t);
    if(*filter.src_ip32 != 0 && *((uint32_t*)hdr->src_ip) != *filter.src_ip32){
        return FILTER_DROP;
    }
    if(*filter.dst_ip32 != 0 && *((uint32_t*)hdr->dst_ip) != *filter.dst_ip32){
        return FILTER_DROP;
    }
    if(*filter.ip_add32 != 0 &&
       *((uint32_t*)hdr->dst_ip) != *filter.ip_add32 &&
       *((uint32_t*)hdr->src_ip) != *filter.ip_add32){
        return FILTER_DROP;
}
    //printf("ip: %x %x, %b\n", *((uint32_t*)hdr->src_ip), *filter.src_ip32, *((uint32_t*)hdr->src_ip) == *filter.src_ip32);
    //I really dont like this hack, but it works.
    l4len = ntohs(hdr->full_len) - hdr->len * 5;
    jprint_ipv4("src_ipv4", hdr->src_ip);
    jprint_ipv4("dst_ipv4", hdr->dst_ip);
    jprintu("ipv4_len", ntohs(hdr->full_len));
    jprintu("ipv4_frag_flag", hdr->frag_and_flags);
    NEXT_HEADER(ipv4_t)
}

static int32_t parse_cip(uint8_t *data, size_t len)
{
    header_ptrs[headers] = data;
    header_types[headers] = TYPE_CIP;
    headers++;
    //printf("=>vlan\n");
    PARSE_START(cip_t);
    int i = 0;
    while (hdr->service >> 7 ==
           0) { //skips this loop for responses (responses have 1 in highest bit)
        uint8_t type = ((data + sizeof(cip_t) + i)[0]);
        //printf("\"type\": \"0x%02x\"\n", type);
        //printf("\"path\": \"0x%02x\"\n", *(data + sizeof(cip_t) + sizeof(uint8_t) + i));
        if (type == 0x91) { //ansi extended symbol segment
            uint8_t len = ((data + sizeof(cip_t) + i)[1]);
            jnewline();
            jprintf("\"path\": \"%.*s\"", len,
                    data + sizeof(cip_t) + sizeof(tl1b_t) + i);
            i += len + 2;
        }else if (type == 0x20) { //class id
            jnewline();
            jprintf("\"path\": \"0x%02x\"", *(data + sizeof(cip_t) + sizeof(uint8_t) + i));
            //printf("0x%02x: 0x%02x\n", type, *(data + sizeof(cip_t) + sizeof(uint8_t) + i));
            i += 1;
        }else if (type == 0x30) { // attribute id
            //printf("0x%02x: 0x%02x\n", type, *(data + sizeof(cip_t) + sizeof(uint8_t) + i));
            i += 1;
        }else if (type == 0x25) { //instance id (16-bit)| different type based on value length https://www.youtube.com/watch?v=sGtY1aPrOMQ
            //printf("0x%02x: 0x%02x\n", type, *(uint16_t*)(data + sizeof(cip_t) + sizeof(uint8_t) + 1 + i));
            i += 3;//2 is the length and 1 padding byte
        }else if (type == 0x24) { //instance id (8-bit) | to be fair it seams that the lowest two bits indicate the size
            //printf("0x%02x: 0x%02x\n", type, *(data + sizeof(cip_t) + sizeof(uint8_t) + i));
            i += 1;
        }else if (type == 0x28) { //8-bit member segment| I'm just configused why sometimes it seams that they are saving every bit and in other parts wasting so much
            //printf("0x%02x: 0x%02x\n", type, *(data + sizeof(cip_t) + sizeof(uint8_t) + i));
            i += 1;
        } else {
            printf("0x%02x: 0x%02x\n", type, *(data + sizeof(cip_t) + sizeof(uint8_t) + i));
            printf("0x%x\n", type);
            return FILTER_HDR_NOT_FOUND;
            ASSERT(0);
        }
        i += sizeof(uint8_t);
        if (hdr->path_len * 2 - i <= 1)
            break;
    }
    return FILTER_ACCEPT;
}

// I parse the explicit and implicit connection packets separately because for
// some reason explicit connection connected address item looks like this
// Type ID: Connected Data Item (0x00b1)
//    Length: 26
//    CIP Sequence Count: ...
//    [CIP DATA]
//
// but implicit connections it looks like this
// Type ID: Connected Data Item (0x00b1)
//    Length: 38
//    [CIP DATA]
//
// For some reason someone somewhere decided that having separate TLV entry for
// seuqnce number is bad or something.
// I don't think they wanted to save types (I've only seen maybe 5 out of the 2^16
// possible used). I don't think it's to save trasmitted data (there is quite a
// bit of wasted and reserved fields).
// Someone just didn't want to have separate entry for seq number. Instead in
// implicit connection sequence number is part of address TLV ("Sequence Address
// Item") which has different type from address item without sequence number.
// Data are then in "Connected data item" (type 0x00b1).
//
// But explicit connections use "Connected Address Item" for addresses which
// contains address, but not sequence number.
// Sequence number is put inside the "Connected data item" with type 0x00b1.
// Which as you might have noticed uses the same type as implicit packets.
// This means that for some reason there are two TLV entries with same type but
// different content.
//
// I especially hate this because every time I read about CIP they tell you
// how it's indenpendent of the networking technology.
// How it doesn't depend of TCP/IP's L1-L4(up to TCP/UDP) but only meaningfull
// way to correctly parse this is to either have two almost identical parsers or
// to check the lower layers.
// Also Why the f does it have 3 transport layers?
//
// Rant over.


static int32_t parse_expl_addr_item(uint8_t *data, size_t len, int seq){
    header_ptrs[headers] = data;
    header_types[headers] =  TYPE_TL;
    headers++;
    ((void)len);
    //printf("=>tl\n");
    PARSE_START(tl_t);
    size_t adjusted_len = hdr->len;
    switch(hdr->type){
        case 0x00b1: //connected data item
            adjusted_len = 2;
        case 0x00b2:// unconnected data item
        case 0x0000:// null address item
        case 0x00a1: // connected address item
        case 0x8000: // Socket address info O->T
        case 0x8001: // Socket address info T->O
            jnewline();
            jprintf("\"tlv%d_type\": %d", seq, hdr->type);
            jnewline();
            jprintf("\"tlv%d_data\": \"0x", seq);
            for(size_t i = 0; i < adjusted_len; i++){
                jprintf("%02x", (data + sizeof(tl_t))[i]);
            }
            jprintf("\"");
            if(hdr->type == 0x00b1)
                return parse_cip(data + sizeof(tl_t) + 2, len - sizeof(tl_t) - 2);
            else
                return sizeof(tl_t) + hdr->len;

        default:
            printf("=> Unknown address type 0x%04x\n", hdr->type);
            return FILTER_HDR_NOT_FOUND;

    }
}

static int32_t parse_expl_enip(uint8_t *data, size_t len){
    header_ptrs[headers] = data;
    header_types[headers] =  TYPE_EX_ENIP;
    headers++;
    //printf("=>expl enip\n");
    PARSE_START(expl_enip_t);
    //printf("address items: %d\n", hdr->num_items);
    jprintu("enip_cmd", ntohs(hdr->cmd));
    jprintu("enip_sess", ntohl(hdr->session));
    jprintu("enip_status", ntohl(hdr->status));
    jprintu("enip_opts", ntohl(hdr->opts));
    jprintu("enip_num_items", ntohs(hdr->num_items));

    switch (hdr->cmd) {
        default:
            printf("Unknows command 0x%04x\n", hdr->cmd);
            ASSERT(0);
            return FILTER_HDR_NOT_FOUND;
        case 0x0065://register session
        case 0x0066://unregister session
            break;

        case 0x0070:
        case 0x006f:
            //printf("sess 0x%04x\n", hdr->session);
            ASSERT(hdr->opts == 0);
            ASSERT(hdr->int_handle == 0);
            //IIRC according to CIP standard this field should allways be 0, but it's not
            //ASSERT(hdr->timeout == 0);
            size_t size = 0;
            for(int i =0; i < hdr->num_items; i++){
                int32_t ret = parse_expl_addr_item(data + sizeof(expl_enip_t) + size, len - sizeof(expl_enip_t) - size, i);
                if (ret < 0)
                    return ret;
                size += ret;
            }
            break;

    }



    return FILTER_ACCEPT;
}

static int32_t parse_tcp(uint8_t *data, size_t len){
    header_ptrs[headers] = data;
    header_types[headers] =  TYPE_TCP;
    headers++;
    PARSE_START(tcp_t);
    if(filter.src_port != 0 && ntohs(hdr->src_port) != filter.src_port) return FILTER_DROP;
    if(filter.dst_port != 0 && ntohs(hdr->dst_port) != filter.dst_port) return FILTER_DROP;
    if(filter.port != 0 && ntohs(hdr->src_port) != filter.port&& ntohs(hdr->dst_port) != filter.port) return FILTER_DROP;
    size_t hdr_len = (ntohs(hdr->flags_len) >> 12) * 4;
    //printf("TCP seq %u\n", ntohl(hdr->seq));
    // This checks for cases where there is no data following the tcp header (mainly happens when device sends ACK without data)
    //printf("%d == %d\n", l4len, hdr_len);
    jprintu("tcp_src_port", ntohs(hdr->src_port));
    jprintu("tcp_dst_port", ntohs(hdr->dst_port));
    jprintu("tcp_seq", ntohs(hdr->seq));
    jprintu("tcp_ack", ntohs(hdr->ack));
    if(l4len == hdr_len)
        return FILTER_ACCEPT;
    // Some devices send single null byte instead of keepalives
    if(l4len - hdr_len == 1 && (data + hdr_len)[0] == 0){
        return FILTER_ACCEPT;
    }
    if(ntohs(hdr->src_port) == 443 || ntohs(hdr->dst_port) == 443)
        return FILTER_ACCEPT;

    if(ntohs(hdr->src_port) == 44818 || ntohs(hdr->dst_port) == 44818){
        return parse_expl_enip(data + hdr_len, len - hdr_len);
    }
    return FILTER_ACCEPT;
}

static int32_t parse_io_enip(uint8_t *data, size_t len){
    header_ptrs[headers] = data;
    header_types[headers] =  TYPE_IO_ENIP;
    headers++;
    ((void)len);
    //printf("=>io enip\n");
    PARSE_START(io_enip_t);
    ASSERT(hdr->num_items == 2);
    ASSERT(hdr->type1 == 0x8002);
    ASSERT(hdr->len == 0x8);
    ASSERT(hdr->type2 == 0x00b1);

    return FILTER_ACCEPT;
}

static int32_t parse_udp(uint8_t *data, size_t len){
    header_ptrs[headers] = data;
    header_types[headers] =  TYPE_UDP;
    headers++;
    //printf("=>udp\n");
    PARSE_START(udp_t);
    if(filter.src_port != 0 && ntohs(hdr->src_port) != filter.src_port) return FILTER_DROP;
    if(filter.dst_port != 0 && ntohs(hdr->dst_port) != filter.dst_port) return FILTER_DROP;
    if(filter.port != 0 && ntohs(hdr->src_port) != filter.port&& ntohs(hdr->dst_port) != filter.port) return FILTER_DROP;
    jprintu("udp_src_port", ntohs(hdr->src_port));
    jprintu("udp_dst_port", ntohs(hdr->dst_port));
    if(ntohs(hdr->src_port) == 2222 || ntohs(hdr->dst_port) == 2222){
        return parse_io_enip(data + sizeof(udp_t), len - sizeof(udp_t));
    }
    return FILTER_ACCEPT;
}

static int32_t parse_vlan(uint8_t *data, size_t len){
    header_ptrs[headers] = data;
    header_types[headers] =  TYPE_VLAN;
    headers++;
    //printf("=>vlan\n");
    PARSE_START(vlan_t);

	int32_t ret = chose_next_header(data + sizeof(vlan_t),
					len - sizeof(vlan_t),
					hdr->next_header);
	if (ret == FILTER_ACCEPT) {
    jprintu("vlan_id", ntohs(hdr->vlan_id));
	}
	return ret;
}

static int32_t parse_eth(uint8_t *data, size_t len)
{
    header_ptrs[headers] = data;
    header_types[headers] = TYPE_ETH2;
    headers++;
    //printf("=>eth\n");
    PARSE_START(ether2_t);
    //printf("Packet: \n");
    //hexdump(data, len);

	//printf("dst mac: ");
	//print_mac(hdr->dst_mac);

	//printf("src mac: ");
	//print_mac(hdr->src_mac);
	if (ntohs(hdr->next_header) < 1500 &&
	    (data + sizeof(ether2_t))[0] == 0xaa &&
	    (data + sizeof(ether2_t))[1] == 0xaa) {
		//probably a 802.3, not ethernet2, so it's likely cdp or something similar
		//return FILTER_HDR_NOT_FOUND;
		return FILTER_ACCEPT;
	}

	int32_t ret = chose_next_header(data + sizeof(ether2_t),
					len - sizeof(ether2_t),
					hdr->next_header);
	if (ret == FILTER_ACCEPT) {
		jprint_mac("src_mac", hdr->src_mac);
		jprint_mac("dst_mac", hdr->dst_mac);
	}
	return ret;
}

static int32_t chose_next_header(uint8_t *data, size_t len, uint16_t nh){
    switch(nh){
        case 0x0081:
            return parse_vlan(data, len);
        case 0x0008:
            return parse_ipv4(data, len);
        case 0x0011:
            return parse_udp(data, len);
        case 0x0006:
            return parse_tcp(data, len);
        case 0x0608: // ARP
        case 0x0001: // ICMP
        case 0x0002: // IGMP
        case 0xdd86: // IPv6 (not used in the dataset)
            return FILTER_ACCEPT;
        default:
             printf("unknown next header: 0x%04x\n", nh);
            return FILTER_HDR_NOT_FOUND;
    }
}



int32_t parse_pb(file_t *f, file_t* outfile){
    size_t block_len;
    size_t packet_len;
    uint8_t* packet_data;
    headers = 0;
    header_num++;
    //printf("=> header %d\n", header_num++);


    //printf("=> PB\n");
    //printf("first type: 0x%08x\n", ((int32_t*)f->data)[0]);
    block_len = ((int32_t*)f->data)[1];
    //printf("len: %ld\n", block_len);
    // ((int32_t*)f->data)[2]; -- interface id
    // ((int32_t*)f->data)[3]; -- timestamp uppper
    // ((int32_t*)f->data)[4]; -- timestamp lower
    packet_len = ((int32_t*)f->data)[5]; //captured packet len
    // ((int32_t*)f->data)[6]; -- orig packet len
    //printf("packet len: %ld\n", packet_len);
    packet_data = (uint8_t*)f->data + 7*4;

    int ret = parse_eth(packet_data, packet_len);

    switch (ret){
        case FILTER_DROP:
            break;
        case FILTER_ACCEPT:
            //if(rand() % 10000 == 0)
            //write(outfile, f->data, block_len);
            memcpy(outfile->data, f->data, block_len);
            outfile->data += block_len;

            if( jq_first != 1 )
                jprintf("\n}");
            break;
        case FILTER_HDR_NOT_FOUND:
            write(unknown_fd, f->data, block_len);
            memcpy(outfile->data, f->data, block_len);
            outfile->data += block_len;
            ASSERT(0);
            break;
        default:
            printf("parse_eth returned unknown return value %d\n", ret);
            break;
    }

    return block_len;
}
