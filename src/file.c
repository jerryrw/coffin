#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>

#include "file.h"
#include "common.h"

int fd = -1;

int create_db_file(char* filename) {
    
    fd = open(filename, O_RDONLY); //check if file exists
    if (fd != -1){
        close(fd);
        printf ("File already exists\n");
        return STATUS_ERROR;
    }

    fd = open(filename, O_RDWR | O_CREAT, 0644);
    if (fd == -1) {
        perror("open");
        return STATUS_ERROR;
    }
    return fd;
}

int open_db_file (char* filename) {
    fd = open(filename, O_RDWR, 0644);
    if (fd == -1) {
        perror("open");
        return STATUS_ERROR;
    }
    return fd;  
}







/*struct database_header_t {
    unsigned short version;
    unsigned short emplyees;
    unsigned int filesize;
};

int main (int argc, char *argv[]) {

    struct database_header_t head = {0};
    struct stat dbstat ={0};

    if (argc != 2) {
        printf ("Usage: %s <filename>\n", argv[0]);
        return 0;
    }

    int fd = open (argv[1], O_RDWR | O_CREAT, 0644);
    if (fd == -1) {
        perror("open");
        return -1;
    }

    if (read (fd, &head, sizeof(head)) != sizeof(head)) {
        perror("read");
        close(fd);
        return -1;
    };

    printf("DB version: %u\n", head.version);
    printf("DB Number of Employees: %u\n", head.emplyees);
    printf("DB File Length: %u\n", head.filesize);

    if (fstat(fd,&dbstat) < 0) {
        perror("fstat");
        close(fd);
        return -1;
    }

    if (dbstat.st_size) {
        printf("Something went wrong\n");
        close(fd);
        return -1;
    }

    close (fd);
    return 0;
}*/