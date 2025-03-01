#include "util.h"
#include "filter.h"
#include <stdio.h>
#include <ctype.h>

int jq_first;
int csv_first_col;

pcap_time_t parse_time(uint32_t lower, uint32_t upper)
{
  uint64_t    time = ((uint64_t)upper) << 32 | ((int64_t)lower);
  pcap_time_t t;
  t.t = time;
  return t;
}

void hexdump(const uint8_t *value, size_t len)
{
  for (unsigned int i = 0; i < len; ++i) {
    fprintf(stdout, "%.2x ", value[i]);
    if (i % 8 == 7) fprintf(stdout, " ");
    if (i % 16 == 15) {
      fprintf(stdout, "   ");
      for (unsigned int j = i - 15; j <= i; ++j) {
        if (isalnum(value[j]))
          fprintf(stdout, "%c", value[j]);
        else
          fprintf(stdout, ".");
      }
      fprintf(stdout, "\n");
    }
  }
  // padding for last line, because it's probably shorter than previous line,
  // padding is added so the ascii representation is aligned
  for (unsigned int i = 0; i <= (16 - len % 16) * 3; ++i)
    fprintf(stdout, " ");
  if (len % 16 < 8) fprintf(stdout, " ");
  fprintf(stdout, "   ");

  for (unsigned int i = len - (len % 16); i < len; ++i) {
    if (isalnum(value[i]))
      fprintf(stdout, "%c", value[i]);
    else
      fprintf(stdout, ".");
  }
  fprintf(stdout, "\n");
}

void __csvnewline(void)
{
  if (csv_first_col) return;
  csv_first_col = 1;
  fprintf(csv_file, "\n");
}

void __csvprint_coma(void)
{
  if (csv_first_col) {
    csv_first_col = 0;
    return;
  }

  fprintf(csv_file, ",");
}

void __csvinit(void)
{
  if (filter.csv_file != NULL) {
    csv_file = fopen(filter.csv_file, "w");
    if (csv_file == NULL) {
      perror("Failed to open csv file");
    }
  }
  if (csv_file == NULL) {
    csv_file = stdout;
  }
  csv_first_col = 1;
}

void __csvprint_u8(uint8_t u8)
{
  fprintf(csv_file, "%u", u8);
}
void __csvprint_u16(uint16_t u16)
{
  fprintf(csv_file, "%u", u16);
}
void __csvprint_i16(int16_t i16)
{
  fprintf(csv_file, "%u", i16);
}
void __csvprint_u32(uint32_t u32)
{
  fprintf(csv_file, "%u", u32);
}
void __csvprint_u64(uint64_t u64)
{
  fprintf(csv_file, "%lu", u64);
}
void __csvprint_i64(int64_t i64)
{
  fprintf(csv_file, "%lu", i64);
}
void __csvprint_time(pcap_time_t time)
{
  uint64_t upper = time.t / 1000000;
  uint64_t lower = time.t - (time.t / 1000000) * 1000000;
  fprintf(csv_file, "%lu.%06lu", upper, lower);
}
void __csvprint_str(char *str)
{
  fprintf(csv_file, "\"%s\"", str);
}

void __csvprint_mac(mac_t mac)
{
  for (int i = 0; i < 5; i++)
    fprintf(csv_file, "%02x:", mac.addr[i]);
  fprintf(csv_file, "%02x", mac.addr[5]);
}
void __csvprint_ipv4(ipv4_addr_t addr)
{
  for (int i = 0; i < 3; i++)
    fprintf(csv_file, "%d.", addr.addr[i]);
  fprintf(csv_file, "%d", addr.addr[3]);
}
