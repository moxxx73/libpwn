#include "libpwn.h"

#include <stdio.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

int pwnErr=0;

// gonna add more features...
void hex_dump(char *data, int length){
    int c=0, x=0, y=0, z=0;
    unsigned char ch;
    while(c < length){
        printf("\t0x%04x: ", c);
        for(;x<6;x++){
            if((c+x) >= length) break;
            printf("%02x ", data[c+x]);
        }
        z = x;
        if(x != 6){
            for(;x<6;x++){
                printf("   ");
            }
        }
        printf("| ");
        for(;y<z;y++){
            ch = data[c+y];
            if(32 <= ch && ch < 127){
                printf("%c", ch);
            }
            else{
                printf(".");
            }
        }
        printf("\n");
        c += x;
        x = 0;
        y = 0;

    }
}

PROC *alloc_proc(void){
    PROC *ret=NULL;
    ret = malloc(sizeof(PROC));
    if(!ret) return NULL;
    ret->pid = 0;
    ret->state = PROC_DEAD;
    ret->stdout = 0;
    ret->stdin = 0;
    ret->stderr = 0;
    ret->prog = NULL;
    return ret;
}

void free_proc(PROC *proc){
    if(proc->prog) free(proc->prog);
    if(proc->rbuf) free(proc->rbuf);
    free(proc);
    return;
}

int kill_proc(PROC *proc){
    close(proc->stdout);
    close(proc->stdin);
    if(kill(proc->pid, SIGKILL)<0){
        if(errno != ESRCH) return -1;
    }
    waitpid(proc->pid, 0, 0);
    proc->state = PROC_DEAD;
    return 0;
}

void kfc_proc(PROC *proc){
    kill_proc(proc);
    free_proc(proc);
    return;
}

PROC *process(char *args[], char blocking){
    PROC *ret=NULL;
    int pid=0;
    int i=0;
    int plen=0;
    int flags=0;
    char *ptr=NULL;
    int STDOUT_PIPE[2];
    int STDIN_PIPE[2];
    ptr = (char *)STDOUT_PIPE;

    for(;i<(sizeof(int)*2);i++){
        ptr[i] = 0x00;
    }
    ptr = (char *)STDIN_PIPE;
    for(i=0;i<(sizeof(int)*2);i++){
        ptr[i] = 0x00;
    }

    ret = alloc_proc();
    if(!ret){
        pwnErr = PROC_ALLOC_ERR;
        return NULL;
    }
    if(blocking) flags = O_NONBLOCK;

    if((pipe2(STDOUT_PIPE, flags) < 0) || (pipe2(STDIN_PIPE, flags) < 0)){
        free(ret);
        pwnErr = PROC_PIPE_ERR;
        return NULL;
    }
    pid = fork();
    if(pid == 0){
        dup2(STDOUT_PIPE[1], STDOUT_FILENO);
        dup2(STDIN_PIPE[0], STDIN_FILENO);
        close(STDOUT_PIPE[1]);
        close(STDIN_PIPE[0]);
        execvp(args[0], args);
        _exit(1);
    }else if(pid < 0){
        free(ret);
        pwnErr = PROC_FORK_ERR;
        return NULL;
    }
    ret->pid = pid;
    ret->stdout = (short)STDOUT_PIPE[0];
    ret->stdin = (short)STDIN_PIPE[1];
    ret->state = PROC_ALIVE;
    ret->rbuf = NULL;
    plen = strlen(args[0]);
    ptr = (char *)malloc(plen);
    if(ptr){
        memcpy(ptr, args[0], plen);
        ret->prog = ptr;
    }
    ret->rbuf = (char *)malloc(PROC_RBUF_SIZE);
    if(ret->rbuf) memset(ret->rbuf, 0, PROC_RBUF_SIZE);
    return ret;
}

int proc_stat(PROC *proc){
    int x=0;
    waitpid(proc->pid, &x, 0);
    return WEXITSTATUS(x);
}

int precvuntil(PROC *proc, char b, int lo){
    char *r_buf=NULL;
    int index=0;
    r_buf = (char *)malloc(PROC_RBUF_SIZE);
    if(!r_buf) return -1;
    memset(r_buf, 0, PROC_RBUF_SIZE);
    while(index<PROC_RBUF_SIZE){
        read(proc->stdout, (r_buf+index), 1);
        if(*(r_buf+index) == b){
            index += 1;
            break;
        }
        index += 1;
    }
    proc->rbuf = r_buf;
    if(lo && ((lo+index) < PROC_RBUF_SIZE)){
        read(proc->stdout, (proc->rbuf+index), lo);
        index += lo;
    }
    return index;
}

int precv(PROC *proc, int size){
    int ret=0;
    if(!proc->rbuf) return -1;
    memset(proc->rbuf, 0, PROC_RBUF_SIZE);
    ret = read(proc->stdout, proc->rbuf, size);
    return ret;
}