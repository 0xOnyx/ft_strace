#include "strace.h"

static int signals_block()
{
    sigset_t blocked = {0};
    int block[] = {SIGHUP, SIGINT, SIGQUIT, SIGPIPE, SIGTERM};

    for (size_t i = 0; i < sizeof (block) / sizeof(block[0]); i++)
        sigaddset(&blocked, block[i]);
    return sigprocmask(SIG_BLOCK, &blocked, NULL);
}


static int signals_unblock()
{
    sigset_t empty_mask;
    sigemptyset(&empty_mask);
    return sigprocmask(SIG_SETMASK, &empty_mask, NULL);
}

int wait_signal(pid_t child_pid, int *status)
{
    if (signals_unblock() < 0
        || waitpid(child_pid, status, 0) < 0
        || signals_block() < 0)
        return (-1);
    return (0);

}

#define SIGNAMEANDNUM(s)  { #s, s }

const char *signame(int s) {
    static struct {
        const char *name;
        int value;
    } known_signals[] = {
            SIGNAMEANDNUM(SIGHUP),
            SIGNAMEANDNUM(SIGINT),
            SIGNAMEANDNUM(SIGQUIT),
            SIGNAMEANDNUM(SIGILL),
            SIGNAMEANDNUM(SIGTRAP),
            SIGNAMEANDNUM(SIGABRT),
            SIGNAMEANDNUM(SIGBUS),
            SIGNAMEANDNUM(SIGFPE),
            SIGNAMEANDNUM(SIGKILL),
            SIGNAMEANDNUM(SIGUSR1),
            SIGNAMEANDNUM(SIGSEGV),
            SIGNAMEANDNUM(SIGUSR2),
            SIGNAMEANDNUM(SIGPIPE),
            SIGNAMEANDNUM(SIGALRM),
            SIGNAMEANDNUM(SIGTERM),
            SIGNAMEANDNUM(SIGSTKFLT),
            SIGNAMEANDNUM(SIGCHLD),
            SIGNAMEANDNUM(SIGCONT),
            SIGNAMEANDNUM(SIGSTOP),
            SIGNAMEANDNUM(SIGTSTP),
            SIGNAMEANDNUM(SIGTTIN),
            SIGNAMEANDNUM(SIGTTOU),
            SIGNAMEANDNUM(SIGURG),
            SIGNAMEANDNUM(SIGXCPU),
            SIGNAMEANDNUM(SIGXFSZ),
            SIGNAMEANDNUM(SIGVTALRM),
            SIGNAMEANDNUM(SIGPROF),
            SIGNAMEANDNUM(SIGWINCH),
            SIGNAMEANDNUM(SIGIO),
            SIGNAMEANDNUM(SIGPWR),
            SIGNAMEANDNUM(SIGSYS)
    };

    for (long unsigned int i = 0; i < sizeof(known_signals)/sizeof(*known_signals); i++) {
        if (s == known_signals[i].value)
            return (known_signals[i].name);
    }
    return NULL;
}

static bool is_file(char *file){
    struct stat stat_buf;

    if (stat(file, &stat_buf) < 0)
        return false;
    if ((stat_buf.st_mode & S_IFMT) == S_IFREG || (stat_buf.st_mode & S_IFMT) == S_IFLNK)
        return true;
    return (true);
}

const char *get_file_exec(char *prog_name){
    static char buff[512];

    if (is_file(prog_name))
        return (prog_name);

    char *path = getenv( "PATH" );
    if (path == NULL)
        return NULL;
    char *token = strtok(path, ":");
    while (token != NULL)
    {
        snprintf(buff, sizeof(buff), "%s/%s", token, prog_name);
        if (is_file(buff))
            return buff;
        token = strtok(NULL, ":");
    }
    return NULL;
}


static void print_addr(void *addr){
    if (addr == NULL)
        fprintf(stderr,"NULL");
    else
        fprintf(stderr,"%p", addr);
}

static void escape(unsigned char *buff, int len){
    char new_buff[4096 * 4];

    int l = 0;
    bzero(new_buff, sizeof(new_buff));
    for (int i = 0; i < len; i++){
        if (buff[i] == '\n')
            l += sprintf(new_buff + l, "\\n");
        else if (buff[i] == '\t')
            l += sprintf(new_buff + l, "\\t");
        else if (buff[i] == '\r')
            l += sprintf(new_buff + l, "\\r");
        else if (buff[i] == '\v')
            l += sprintf(new_buff + l, "\\v");
        else if (buff[i] == '\f')
            l += sprintf(new_buff + l, "\\f");
        else if (buff[i] < 32 || buff[i] > 126)
            l += sprintf(new_buff + l, "\\%d", buff[i]);
        else
            new_buff[l++] = buff[i];
    }
    memcpy(buff, new_buff, l);
}

static void print_str(pid_t pid, void *addr){
    struct iovec local[1];
    struct iovec remote[1];
    unsigned char buff[4096];

    local[0].iov_base = buff;
    local[0].iov_len = sizeof(buff);
    remote[0].iov_base = addr;
    remote[0].iov_len = sizeof(buff);
    ssize_t len = process_vm_readv(pid, local, 1, remote, 1, 0);
    if (len < 0)
        fprintf(stderr,"%#lx", (long unsigned int)addr);
    else{
        int len_str = memchr(local[0].iov_base, 0, sizeof(buff)) - local[0].iov_base;

        escape(local[0].iov_base, len_str);
        if (len_str > 48)
            fprintf(stderr, "\"%.32s\"...", (char *)local[0].iov_base);
        else
            fprintf(stderr, "\"%s\"", (char *)local[0].iov_base);
    }

}

void print_syscall(pid_t child_pid, t_syscall syscall, ...){
    va_list ap;

    va_start(ap, syscall);
    fprintf(stderr,"%s(", syscall.name);
    for (int i = 0; i < MAX_ARGS; i++){
        enum e_type_syscall type = syscall.type_arg[i];
        switch (type) {
            case T_CHAR:
            case T_SHORT:
            case T_UCHAR:
            case T_INT:
                fprintf(stderr,"%d", va_arg(ap, int));
                break;
            case T_LINT:
                fprintf(stderr,"%ld", va_arg(ap, long));
                break;
            case T_LLINT:
                fprintf(stderr,"%lld", va_arg(ap, long long));
                break;
            case T_USHORT:
            case T_UINT:
                fprintf(stderr,"%u", va_arg(ap, unsigned int));
                break;
            case T_ULINT:
                fprintf(stderr,"%ld", va_arg(ap, unsigned long));
                break;
            case T_ULLINT:
                fprintf(stderr,"%lld", va_arg(ap, unsigned long long));
                break;
            case T_FLOAT:
            case T_DOUBLE:
                fprintf(stderr,"%f", va_arg(ap, double));
                break;
            case T_LDOUBLE:
                fprintf(stderr,"%Lf", va_arg(ap, long double));
                break;
            case T_ADDR:
                print_addr(va_arg(ap, void *));
                break;
            case T_HEX:
                fprintf(stderr,"0x%lx", va_arg(ap, unsigned long));
                break;
            case T_BUFF:
                fprintf(stderr,"0x%lx", va_arg(ap, unsigned long));
                break;
            case T_STR:
                print_str(child_pid, va_arg(ap, void *));
                break;
            case T_UNKNOWN:
                fprintf(stderr,"UNKNOWN");
                break;
            case T_NONE:
                break;
        }
        if (i < MAX_ARGS - 1 && syscall.type_arg[i + 1] != T_NONE)
            fprintf(stderr,", ");
    }
    va_end(ap);
    fprintf(stderr,")");
}

void print_ret(long ret, enum e_type_syscall type){
    if (ret < 0){
        fprintf(stderr, " = -1 %s\n", strerror(-ret));
    }
    else {
        if (type == T_INT)
            fprintf(stderr," = %ld\n", ret);
        else
            fprintf(stderr," = %#lx\n", ret);
    }
}
