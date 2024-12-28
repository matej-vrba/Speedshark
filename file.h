#ifndef FILE_H_
#define FILE_H_
#include <sys/stat.h>
       #include <stddef.h>


typedef struct{
    char* data;
    struct stat sb;
    int fd;
    char* __orig_data;
    int __truncate;
} file_t ;

file_t open_infile(const char* filename);
file_t open_outfile(const char* filename, size_t max_size);
void close_file(file_t *f);

#endif // FILE_H_
