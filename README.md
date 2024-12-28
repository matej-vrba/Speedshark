# Speedshark - minimal, faster tshark/wireshark alternative

I've made this tool for faster pcap filtering because tshark/wireshark/scapy are not only slow, but also consume a lot of memory.
Testing on a 3.2GiB pcap, tshark took something around 5 to 7hours and few gigabytes of ram.
Speedshark finished in 3.2 seconds.

There are more than one reason for this speed increase:
- I've only implemented the bare minimum to process what I need (Ethernet2, IPv4, TCP, UDP, paritally CIP/ENIP).
- Speedshark doesn't make any copies of data (except for packets matching filter - but even that is only a single copy). This helps with speed and memory requirements
- Filtering is implemented as part of source code. Speedshark only takes two arguments - input file and output file. Unlike tshark the filter is not passed on command line, but it's written in C in source (`pb.c`).

Speedshark also supports json output (but since for now it's outputted to stdout the speed drops significantly).

For now only pcapng files are supported. If you have any issues make sure your files are in pcapng format (not pcap) like this `tshark -r in.pcap -w out.pcap`. Tshark is quite fast when you don't include filters.


The code is quite a mess. If you're interested in using this, open an issue and I'll clean it a bit and help you understand it.

Speedshark probably won't work on big endian systems. I only have an intel machine, so I wasn't able to get it working on big endian CPUs.

## Filtering

First input pcap file is mapped into memory.

Filtering is implemented in `pb.c`.
The basic principle is quite simple. Each protocol gets a c struct representing the packet structure and parsing functions.
First `parse_eth` function is called. This function is responsible for parsing the Ethernet2 header.
Parsing is done by taking a pointer to the input file at a correct offset and casting it to the struct representing that protocol's header.
Parsing function can either make a decision and return `FILTER_DROP` or `FILTER_ACCEPT` to either copy current packet to output file or not or it can leave this decission to upper layer parser function.
This is usually done using code like this:

``` c
return parse_vlan(data + sizeof(current_proto_t), len - sizeof(current_proto_t));
```

Based on value returned from `parse_eth` (which itself probably left the decision to upper layer parsers) the packet is etiher dropped or saved.

There is also third value `FILTER_HDR_NOT_FOUND`. I usually use this to signalize that the parser encountered some data that it doesn't know how to parse.
E.g. unknown value in `next_header` field or port.
If this value is returned the packet is saved into `unknown.pcapng`, processing is stopped and current parsed packet is printed.

Decision values (`FILTER_DROP`, `FILTER_ACCEPT`, ...) have negative value.
Some parsers also return positive value indicating number of bytes parsed instead.
This is used when parser of single protocol is split into multiple parser functions.
At the time of wirting this can be seen in `parse_expl_enip`.
There if `parse_expl_addr_item` made a filtering decision (return value is negative) we return that. If not it returned number of processed bytes and we continue.
However use this with care. If the positive value "leak" and is returned from `parse_eth`, the packet will be dropped.

There is also very basic filtering using environment variables (see `filter.c` for aviable options).

## dump function

speedshark's filter includes a `dump` function.
This function can be called independenly but it's also called when `ASSERT` fails.
When called it prints all parsed layers of currrent packet.

This is implemented using `header_ptrs`, `headers` and `header_types` global variables.
`packets` holds number of parsed headers/layers.
Other two variables hold array pointing to starts of individual headers and header types.
`dump` function then simply goes through the array and based on type parses and prints the header.
This function is very handy for debugging.


## Compiling

There are two makefiles. `Makefile` just compiles the program. `Makefile.pgo` compiles with PGO (Profile-guided optimization). PGO version compiles program first time, runs it few times on a pcap that you need to supply and then compiles again with profile data generated from running it.

If you also have large input dataset you can use commented out code in `pb.c` near the end that randomly saves 1/10_000 of the packets to generate random smaller sample used to generate the profiler data faster.
Also uncomment srand in main.

From my testing PGO didn't result in a measurable improvement.

# Contact
I'm mainly using gitlab (https://gitlab.com/matej-vrba/speedshark) so I would appreciate if you opened issue there. But I'm also mirroring this project to github, so if you open an issue there I'll probably see it too.
