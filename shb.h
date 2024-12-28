// parses Section Header Block, prints some info and returns size
#ifndef SHB_H_
#define SHB_H_

#include <stdint.h>

#include "file.h"


int32_t parse_shb(file_t* f, file_t* outfile);


#endif // SHB_H_
