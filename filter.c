#include "filter.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void load_ip(const char *env, uint8_t *dst)
{
	char *tmp = getenv(env);
	if (tmp == NULL) {
		*((uint32_t *)dst) = 0;
		return;
	}
	char *oct = strtok(tmp, ".");
	int64_t res = strtol(oct, NULL, 10);
	if (res < 0 || res > 255) {
		fprintf(stderr, "Invalid ip address in %s\n", env);
		*((uint32_t *)dst) = 0;
		return;
	}
	dst[0] = res;
	for (int i = 1; i < 4; i++) {
		oct = strtok(NULL, ".");
		res = strtol(oct, NULL, 10);
		if (res < 0 || res > 255) {
			fprintf(stderr, "Invalid ip address in %s\n", env);
			*((uint32_t *)dst) = 0;
			return;
		}
		dst[i] = res;
	}
}

static void load_port(const char *env, uint16_t *dst)
{
	char *tmp = getenv(env);
	if (tmp == NULL) {
		*dst = 0;
		return;
	}
	int64_t res = strtol(tmp, NULL, 10);
	if (res <= 0 || res > 0xffff) {
		fprintf(stderr, "Invalid port %ld\n", res);
		*dst = 0;
		return;
	}
	*dst = (uint16_t)res;
}

static void load_str(const char *env, char **dst)
{
	*dst = getenv(env);
}

void load_filters(void)
{
	char *env;
	load_ip("SSHARK_SRC_IP", &filter.src_ip);
	load_ip("SSHARK_DST_IP", &filter.dst_ip);
	load_ip("SSHARK_IP_ADD", &filter.ip_add);
	load_port("SSHARK_SRC_PORT", &filter.src_port);
	load_port("SSHARK_DST_PORT", &filter.dst_port);
	load_port("SSHARK_PORT", &filter.port);
	load_str("SSHARK_JSON_FILE", &filter.json_file);
    filter.src_ip32 = (uint32_t*)filter.src_ip;
    filter.dst_ip32 = (uint32_t*)filter.dst_ip;
    filter.ip_add32 = (uint32_t*)filter.ip_add;
}
