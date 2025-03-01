#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>



#include "types.h"
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

char* header_names[] = {
    [TYPE_ETH2] =  "ETH2",
    [TYPE_VLAN] =  "VLAN",
    [TYPE_IPv4] =  "IPv4",
    [TYPE_TCP] =  "TCP",
    [TYPE_UDP] =  "UDP",
    [TYPE_IO_ENIP] =  "IO_ENIP",
    [TYPE_EX_ENIP] =  "EX_ENIP",
    [TYPE_TL] =  "TL",
    [TYPE_CIP] =  "CIP",
};

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
        } else if (header_types[i]== TYPE_CIP){
            DUMP_PREP(cip_t);
            indent();
            iprintf("service: 0x%08x\n", hdr->service);
        } else{
            printf("dump print function not implemented for type 0x%x\n", header_types[i]);
            assert(0);
        }
    }
}


#if 0
#define parser_trace(name) do{printf(name);}while(0)
#else
#define parser_trace(name) do{}while(0)
#endif


static int32_t chose_next_header(uint8_t *data, size_t len, uint16_t nh);

static int32_t parse_ipv4(uint8_t *data, size_t len){
    header_ptrs[headers] = data;
    header_types[headers] =  TYPE_IPv4;
    headers++;
    parser_trace("=>ipv4\n");

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
    (void)len;
    header_ptrs[headers] = data;
    header_types[headers] = TYPE_CIP;
    headers++;
    parser_trace("=>cip\n");
    PARSE_START(cip_t);
    int i = 0;
    while (hdr->service >> 7 == 0) { //skips this loop for responses (responses have 1 in highest bit)
        uint8_t type = *((data + sizeof(cip_t) + i));
        //printf("\"type\": \"0x%02x\"\n", type);
        //printf("\"path\": \"0x%02x\"\n", *(data + sizeof(cip_t) + sizeof(uint8_t) + i));
        if (type == 0x91) { //ansi extended symbol segment
            uint8_t len = *((data + sizeof(cip_t) + i + 1));
            jnewline();
            jprintf("\"path\": \"%.*s\"", len,
                    data + sizeof(cip_t) + sizeof(tl1b_t) + i);
            if (len % 2 == 1)
                i += len + 2;
            else
                i += len + 1;
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
    size_t path_len = i;

    //response has two aditional status bytes
    if (hdr->service >> 7 != 0) path_len += 2;

    if ((hdr->service & ~(1 << 7)) == 0x0a) { //multi service
      uint8_t *start = data + sizeof(cip_t) + path_len;
      size_t num = *(uint16_t*)(start);
      for(int i = 0; i < num; i++){
        uint16_t offset = start[(i * 2) + 2];
        size_t total_offset = sizeof(cip_t) + path_len + offset;
        parse_cip(data + total_offset, len - total_offset);
      }
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
// They have same type but different data part. No idea why, but it proves that
// "all well designed protocols use TLV" doesn't work the other way.

static int32_t parse_expl_addr_item(uint8_t *data, size_t len, int seq){
    (void)seq;
    header_ptrs[headers] = data;
    header_types[headers] =  TYPE_TL;
    headers++;
    ((void)len);
    parser_trace("=>tl\n");
    PARSE_START(tl_t);
    size_t adjusted_len = hdr->len;
    switch(hdr->type){
        case 0x00b1: //connected data item
            adjusted_len = 2;
            [[fallthrough]];
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
    parser_trace("=>expl enip\n");
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
    parser_trace("=>tcp\n");
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
    parser_trace("=>io enip\n");
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
    parser_trace("=>udp\n");
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
    return FILTER_DROP;
    header_ptrs[headers] = data;
    header_types[headers] =  TYPE_VLAN;
    headers++;
    parser_trace("=>vlan\n");
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
    parser_trace("=>eth\n");
    PARSE_START(ether2_t);
    //printf("Packet: \n");
    //hexdump(data, len);

	//printf("dst mac: ");
	//print_mac(hdr->dst_mac);

	//printf("src mac: ");
	//print_mac(hdr->src_mac);
	if (ntohs(hdr->next_header) < 1500
	    ) {
		//probably a 802.3, not ethernet2, so it's likely cdp or something similar
		//return FILTER_HDR_NOT_FOUND;
    //printf("Dropping %x\n", hdr->next_header);
		return FILTER_ACCEPT;
	}
	if(hdr->next_header == 0xcc88){//Ignore LLDP
	       return FILTER_DROP; 
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
            return FILTER_DROP;
            return FILTER_ACCEPT;
        default:
             printf("unknown next header: 0x%04x\n", nh);
            return FILTER_HDR_NOT_FOUND;
    }
}

static void packet_to_csv_line(int num, pcap_time_t time)
{
  static pcap_time_t start = { .t = 0 };
  if (start.t == 0) start.t = time.t;
  pcap_time_t t_relative = { .t = time.t - start.t };
  int         vlan_id = -1;
  uint8_t    *data;
  size_t      len;
  mac_t       src_mac;
  mac_t       dst_mac;
  uint8_t     ipv4_ihl;
  uint8_t     ipv4_dscp;
  ipv4_addr_t ip_src;
  ipv4_addr_t ip_dst;
  uint32_t    tcp_seq = 0;
  uint32_t    tcp_ack = 0;
  uint16_t    sport = 0;
  uint16_t    dport = 0;
  char        flags[10] = "";
  int64_t     trans_len = -1; //TODO
  int64_t     enip_sess = -1;
  size_t      enip_fields_offset = 0;
  char        enip_fields[128] = "";
  int64_t     cid = -1;
  int32_t     cip_seq = -1;
  int16_t     cip_service = -1;
  size_t      cip_service_path_len = 0;
  char        cip_service_path[128] = "";

  for (int i = 0; i < headers; i++) {
    if (header_types[i] == TYPE_VLAN) {
      DUMP_PREP(vlan_t);
      vlan_id = hdr->vlan_id;
    } else if (header_types[i] == TYPE_ETH2) {
      DUMP_PREP(ether2_t);
      memcpy(src_mac.addr, hdr->src_mac, 6);
      memcpy(dst_mac.addr, hdr->dst_mac, 6);
    } else if (header_types[i] == TYPE_TCP) {
      DUMP_PREP(tcp_t);
      tcp_seq = htonl(hdr->seq);
      tcp_ack = htonl(hdr->ack);
      sport = htons(hdr->src_port);
      dport = htons(hdr->dst_port);
      size_t   flags_len = 0;
      uint16_t f_l = htons(hdr->flags_len);
      if (f_l & 1 << 0) flags[flags_len++] = 'F';
      if (f_l & 1 << 1) flags[flags_len++] = 'S';
      if (f_l & 1 << 2) flags[flags_len++] = 'R';
      if (f_l & 1 << 3) flags[flags_len++] = 'P';
      if (f_l & 1 << 4) flags[flags_len++] = 'A';
      if (f_l & 1 << 5) flags[flags_len++] = 'U';
      if (f_l & 1 << 6) flags[flags_len++] = 'E';
      if (f_l & 1 << 7) flags[flags_len++] = 'C';
      if (f_l & 1 << 8) flags[flags_len++] = 'c';
      flags[flags_len] = '\0';

    } else if (header_types[i] == TYPE_EX_ENIP) {
      DUMP_PREP(expl_enip_t);
      enip_sess = hdr->session;

    } else if (header_types[i] == TYPE_TL) {
      DUMP_PREP(tl_t);
      sprintf(enip_fields + enip_fields_offset, "f:%04x,", hdr->type);
      if (hdr->type == 0xa1) {
        cid = *(uint32_t *)(data + sizeof(tl_t));
      } else if (hdr->type == 0xb1) {
        cip_seq = *(uint16_t *)(data + sizeof(tl_t));
      }

      enip_fields_offset += 7;
    } else if (header_types[i] == TYPE_CIP) {
      DUMP_PREP(cip_t);
      cip_service = hdr->service;
      sprintf(cip_service_path + cip_service_path_len, "s:%02x,", cip_service);
      cip_service_path_len += 5;

      if (hdr->service >> 7 != 0){
          sprintf(cip_service_path + cip_service_path_len, "r:%02x,", data[2]);
          cip_service_path_len += 5;
      }

      char *path = data + sizeof(cip_t);
      for (int i = 0; i < hdr->path_len;) {
        uint8_t segment_type = path[0];
        switch (segment_type) {
          case 0x91: //ANSI extended symbol segment
            strncat(cip_service_path + cip_service_path_len, path + 2, path[1]);
            size_t segment_len = path[1];
            if (path[1] % 2 == 1) segment_len++;
            segment_len += 2; // "header" (type and len) len
            cip_service_path_len += path[1];
            path += segment_len;

            i += segment_len;

            break;
          case 0x20: // 8-bit class
            sprintf(cip_service_path + cip_service_path_len, "c:%02x,", *(uint8_t *)(path + 1));
            cip_service_path_len += 5;
            i += 2;
            path += 2;
            break;
          case 0x24: // 8-bit instance
            sprintf(cip_service_path + cip_service_path_len, "i:%02x,", *(uint8_t *)(path + 1));
            cip_service_path_len += 5;
            i += 2;
            path += 2;
            break;
          case 0x25: // 16-bit instance
            sprintf(cip_service_path + cip_service_path_len, "i:%02x,", *(uint16_t *)(path + 2));
            cip_service_path_len += 5;
            i += 4;
            path += 4;
            break;
          default:
          fprintf(stderr, "Unknown segment type 0x%02x\n", segment_type);
            ASSERT(0 == 1);
        }
      }
      cip_service_path[cip_service_path_len - 1] = ';';
    } else if (header_types[i] == TYPE_IPv4) {
      DUMP_PREP(ipv4_t);
      ipv4_ihl = hdr->len;
      ipv4_dscp = hdr->dscp;
      memcpy(ip_src.addr, hdr->src_ip, 4);
      memcpy(ip_dst.addr, hdr->dst_ip, 4);
    }
  }

  if (cip_service_path_len != 0) cip_service_path[cip_service_path_len - 1] = '\0';
  if (enip_fields_offset != 0) enip_fields[enip_fields_offset - 1] = '\0';
  csvprint(num);
  csvprint(header_names[header_types[headers - 1]]);
  csvprint(t_relative);
  csvprint(time);
  csvprint(src_mac);
  csvprintnn(vlan_id);
  csvprint(dst_mac);
  csvprint(ipv4_ihl);
  csvprint(ipv4_dscp);
  csvprint(ip_src);
  csvprint(ip_dst);
  csvprintnz(tcp_seq);
  csvprintnz(tcp_ack);
  csvprintnz(sport);
  csvprintnz(dport);
  if (flags[0] != '\0')
    csvprint(flags);
  else
    csvprint("");

  csvprintnn(trans_len);
  csvprintnn(enip_sess);
  csvprint(enip_fields);
  csvprintnn(cid);
  csvprintnn(cip_seq);
  csvprintnn(cip_service);
  csvprint(cip_service_path);
}

int32_t parse_pb(file_t *f, file_t* outfile){
    static size_t num_accepted = 0;
    size_t block_len;
    size_t packet_len;
    uint8_t* packet_data;
    headers = 0;
    header_num++;
    //printf("=> header %d\n", header_num++);


    //printf("=> PB\n");
    //printf("first type: 0x%08x\n", ((int32_t*)f->data)[0]);
    block_len = ((int32_t*)f->data)[1];
    // ((int32_t*)f->data)[2]; -- interface id
    //printf("len: %ld\n", block_len);
    // ((int32_t*)f->data)[3]; -- timestamp uppper
    // ((int32_t*)f->data)[4]; -- timestamp lower
    packet_len = ((int32_t*)f->data)[5]; //captured packet len
    // ((int32_t*)f->data)[6]; -- orig packet len
    //printf("packet len: %ld\n", packet_len);
    packet_data = (uint8_t*)f->data + 7*4;

    int32_t ret = parse_eth(packet_data, packet_len);

    switch (ret){
        case FILTER_DROP:
            break;
        case FILTER_ACCEPT:
            //if(rand() % 10000 == 0)
            //write(outfile, f->data, block_len);
            memcpy(outfile->data, f->data, block_len);
            outfile->data += block_len;

            if( jq_first != 1 ){
                jprintf("\n}");
            }
#ifdef ENABLE_CSV
            pcap_time_t time = parse_time(((int32_t *)f->data)[4], ((int32_t *)f->data)[3]);
            packet_to_csv_line(num_accepted++, time);
#endif
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
