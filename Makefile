##
# Project Title
#
# @file
# @version 0.1

CC=clang
CFLAGS += -O3 -ffast-math -pedantic -Wall -Wextra  -march=native -flto
LDFLAGS += -march=native -flto  -O3 -ffast-math
SRCS =  $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(SRCS))
DEPS = $(patsubst %.c,%.d,$(SRCS))

.PHONY: all clean run

all:  speedshark

clean:
	rm -rf $(OBJS) $(DEPS) speedshark speedshark.prof default.profdata ./default-*.rawprof ./tmp

run: all
	SSHARK_SRC_PORT="22" SSHARK_SRC_IP="192.168.1.200" ./speedshark 100.pcapng out.pcapng

speedshark:  $(OBJS)
	$(CC) $(LDFLAGS) $^ -o $@

-include $(DEPS)

%.o: %.c
	$(CC) $(CFLAGS)  -MMD -MP -c $< -o $@


# end
