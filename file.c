#include "file.h"
#include <stdio.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>





file_t open_infile(const char* filename){
    file_t f ;
    // Open the file
    f.fd = open(filename, O_RDONLY);
    if (f.fd == -1) {
        char buff[64];
        sprintf(buff, "Error opening file %s", filename);
        perror(buff);
        goto exit_failure;
    }

    // Get the size of the file
    if (fstat(f.fd, &f.sb) == -1) {
        perror("Error getting file size");
        goto exit_failure;
    }

    // Memory-map the file
    f.data = mmap(NULL, f.sb.st_size, PROT_READ, MAP_PRIVATE, f.fd, 0);
    f.__orig_data = f.data;
    if (f.data == MAP_FAILED) {
        char buff[64];
        sprintf(buff, "Error mapping file %s", filename);
        perror(buff);
        goto exit_failure;
    }
    f.__truncate = 0;
    return f;
    exit_failure:
        if(f.fd > 0)
            close(f.fd);
        f.fd = 0;
        f.data = NULL;
        return f;
}
file_t open_outfile(const char* filename, size_t max_size){
    file_t f ;
    // Open the file
    f.fd = open(filename, O_RDWR|O_CREAT|O_TRUNC, 0644);
    if (f.fd == -1) {
        char buff[64];
        sprintf(buff, "Error opening file %s", filename);
        perror(buff);
        goto exit_failure;
    }
    // Extend the file to the mapped size
    if (ftruncate(f.fd, max_size) == -1) {
        perror("ftruncate");
        goto exit_failure;
    }

    // Get the size of the file
    if (fstat(f.fd, &f.sb) == -1) {
        perror("Error getting file size");
        goto exit_failure;
    }

    // Memory-map the file
    f.data = mmap(NULL, max_size, PROT_WRITE , MAP_SHARED, f.fd, 0);
    if (f.data == MAP_FAILED) {
        char buff[64];
        sprintf(buff, "Error mapping file %s", filename);
        perror(buff);
        goto exit_failure;
    }
    f.__orig_data = f.data;
    f.__truncate = 1;
    return f;
    exit_failure:
        if(f.fd > 0)
            close(f.fd);
        f.fd = 0;
        f.data = NULL;
        return f;
}

void close_file(file_t *f){
    if(f->__truncate){
        msync(f->__orig_data, f->data - f->__orig_data, MS_SYNC);
        if (ftruncate(f->fd, f->data - f->__orig_data) == -1){
            perror("failed to ftruncate before closing");
        }
    }
    if (munmap(f->__orig_data, f->sb.st_size) == -1) {
        perror("Error unmapping file");
    }
    if (close(f->fd) != 0){
        perror("Failed to close file");
    }
}
