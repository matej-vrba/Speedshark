// Parases packet block and returns size;
#ifndef PB_H_
#define PB_H_

#include <stdint.h>
#include "file.h"


int32_t parse_pb(file_t *f, file_t* outfile);
void dump(void);


#endif // PB_H_
