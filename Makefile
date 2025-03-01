##
# Project Title
#
# @file
# @version 0.1

CC=clang
CFLAGS += -O3 -ffast-math -pedantic -Wall -Wextra  -march=native -flto -std=gnu17 -fsanitize=address
LDFLAGS += -march=native -flto  -O3 -ffast-math -fsanitize=address
SRCS =  $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(SRCS))
DEPS = $(patsubst %.c,%.d,$(SRCS))

.PHONY: all clean run

all:  speedshark

clean:
	rm -rf $(OBJS) $(DEPS) speedshark speedshark.prof default.profdata ./default-*.rawprof ./tmp

run: all
	SSHARK_SRC_PORT="22" SSHARK_SRC_IP="192.168.1.200" ./speedshark 100.pcapng out.pcapng

run_csv: all
	#./speedshark 10.pcap tmp.pcap
	SSHARK_CSV_FILE=tmp.csv ./speedshark multi_request10.pcap tmp.pcap
	#cat tmp.csv | cut -d, -f 12,13,14,15,16,17,18 | column -t -s ,
	cat tmp.csv | cut -d, -f 1,18,19,20,21,22,23 | column -t -s ,

speedshark:  $(OBJS)
	$(CC) $(LDFLAGS) $^ -o $@

-include $(DEPS)

%.o: %.c
	$(CC) $(CFLAGS)  -MMD -MP -c $< -o $@


# end
