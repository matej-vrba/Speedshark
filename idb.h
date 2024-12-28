// parses Interface Description Block, prints some info and returns size
#ifndef IDB_H_
#define IDB_H_

#include <stdint.h>
#include "file.h"


int32_t parse_idb(file_t *f, file_t* outfile);


#endif // IDB_H_
