#define _GNU_SOURCE

#define PWN_VERSION "(V_V)(^) 0.01"

#define PROC_ALLOC_ERR 0x01
#define PROC_PIPE_ERR 0x02
#define PROC_FORK_ERR 0x03
#define ERR_LIST_LEN 3

const char *err_str[ERR_LIST_LEN] = {
    "Failed to allocate PROC object",
    "pipe() failed!",
    "fork() failed!"
};

#define pwn_strerror(errnum) (err_str[errnum])

extern int pwnErr;

#define PROC_DEAD 0x00
#define PROC_ALIVE 0x01

#define PROC_BLOCK 0x00
#define PROC_NONBLOCK 0x01

#define PROC_RBUF_SIZE 255

typedef struct pwn_proc_struct{
    int pid;
    char state;
    short stdout;
    short stdin;
    short stderr;
    char *prog;
    char *rbuf;
} PROC;

/* dumps raw data as hex | ascii */
void hex_dump(char *data, int length);

void free_proc(PROC *proc);

int kill_proc(PROC *proc);

PROC *process(char *args[], char blocking);

int recvuntil(PROC *proc, char b, int lo);