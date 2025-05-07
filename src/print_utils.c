#include "print_utils.h"
#include "syscall.h"
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <signal.h>
#include <sched.h>
#include <sys/wait.h>


// Définitions des types d'arguments pour print_syscall
enum e_arg_type {
    ARG_INT,
    ARG_UINT,
    ARG_LONG,
    ARG_ULONG,
    ARG_PTR,
    ARG_STR,
    ARG_OPEN_FLAGS,
    ARG_MODE_T,
    ARG_MMAP_PROT,
    ARG_MMAP_FLAGS,
    ARG_SIGNAL,
    ARG_WAIT_OPTIONS,
    ARG_CLONE_FLAGS
};

// Définitions des types de retour pour print_ret
enum e_ret_type {
    TYPE_VOID,
    TYPE_INT,
    TYPE_PID_T,
    TYPE_SSIZE_T,
    TYPE_PTR
};

// Structure étendue pour t_syscall
typedef struct syscall_ext_s {
    char *name;
    enum e_arg_type args[6];
    size_t nb_args;
    enum e_ret_type ret_type;
} t_syscall_ext;

static const char *open_flags[] = {
    "O_RDONLY", "O_WRONLY", "O_RDWR", "O_CREAT", "O_EXCL", "O_NOCTTY",
    "O_TRUNC", "O_APPEND", "O_NONBLOCK", "O_SYNC", "O_ASYNC", "O_DIRECT",
    "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_PATH", "O_TMPFILE"
};

static const int open_flags_values[] = {
    O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_EXCL, O_NOCTTY,
    O_TRUNC, O_APPEND, O_NONBLOCK, O_SYNC, O_ASYNC, O_DIRECT,
    O_DIRECTORY, O_NOFOLLOW, O_CLOEXEC, O_PATH, O_TMPFILE
};

void print_open_flags(int flags) {
    bool first = true;
    printf("0x%x", flags);
    for (size_t i = 0; i < sizeof(open_flags) / sizeof(open_flags[0]); i++) {
        if (flags & open_flags_values[i]) {
            printf("%s%s", first ? " (" : "|", open_flags[i]);
            first = false;
        }
    }
    if (!first)
        printf(")");
}

static const char *mode_flags[] = {
    "S_ISUID", "S_ISGID", "S_ISVTX", "S_IRUSR", "S_IWUSR", "S_IXUSR",
    "S_IRGRP", "S_IWGRP", "S_IXGRP", "S_IROTH", "S_IWOTH", "S_IXOTH"
};

static const int mode_flags_values[] = {
    S_ISUID, S_ISGID, S_ISVTX, S_IRUSR, S_IWUSR, S_IXUSR,
    S_IRGRP, S_IWGRP, S_IXGRP, S_IROTH, S_IWOTH, S_IXOTH
};

void print_mode_t(unsigned int mode) {
    bool first = true;
    printf("0%o", mode & 0777);
    for (size_t i = 0; i < sizeof(mode_flags) / sizeof(mode_flags[0]); i++) {
        if (mode & mode_flags_values[i]) {
            printf("%s%s", first ? " (" : "|", mode_flags[i]);
            first = false;
        }
    }
    if (!first)
        printf(")");
}

static const char *mmap_prot[] = {
    "PROT_NONE", "PROT_READ", "PROT_WRITE", "PROT_EXEC"
};

static const int mmap_prot_values[] = {
    PROT_NONE, PROT_READ, PROT_WRITE, PROT_EXEC
};

void print_mmap_prot(int prot) {
    bool first = true;
    printf("0x%x", prot);
    for (size_t i = 0; i < sizeof(mmap_prot) / sizeof(mmap_prot[0]); i++) {
        if (prot & mmap_prot_values[i]) {
            printf("%s%s", first ? " (" : "|", mmap_prot[i]);
            first = false;
        }
    }
    if (!first)
        printf(")");
}

static const char *mmap_flags[] = {
    "MAP_SHARED", "MAP_PRIVATE", "MAP_FIXED", "MAP_ANONYMOUS", "MAP_DENYWRITE",
    "MAP_EXECUTABLE", "MAP_LOCKED", "MAP_NORESERVE", "MAP_POPULATE", "MAP_NONBLOCK",
    "MAP_STACK", "MAP_HUGETLB", "MAP_SYNC", "MAP_FIXED_NOREPLACE"
};

static const int mmap_flags_values[] = {
    MAP_SHARED, MAP_PRIVATE, MAP_FIXED, MAP_ANONYMOUS, MAP_DENYWRITE,
    MAP_EXECUTABLE, MAP_LOCKED, MAP_NORESERVE, MAP_POPULATE, MAP_NONBLOCK,
    MAP_STACK, MAP_HUGETLB, MAP_SYNC, MAP_FIXED_NOREPLACE
};

void print_mmap_flags(int flags) {
    bool first = true;
    printf("0x%x", flags);
    for (size_t i = 0; i < sizeof(mmap_flags) / sizeof(mmap_flags[0]); i++) {
        if (flags & mmap_flags_values[i]) {
            printf("%s%s", first ? " (" : "|", mmap_flags[i]);
            first = false;
        }
    }
    if (!first)
        printf(")");
}

// Utilisation de valeurs constantes pour les signaux RT
#define SIGRTMIN_VAL 32
#define SIGRTMAX_VAL 64

static const char *signals[] = {
    "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT", "SIGBUS",
    "SIGFPE", "SIGKILL", "SIGUSR1", "SIGSEGV", "SIGUSR2", "SIGPIPE", "SIGALRM",
    "SIGTERM", "SIGSTKFLT", "SIGCHLD", "SIGCONT", "SIGSTOP", "SIGTSTP", "SIGTTIN",
    "SIGTTOU", "SIGURG", "SIGXCPU", "SIGXFSZ", "SIGVTALRM", "SIGPROF", "SIGWINCH",
    "SIGIO", "SIGPWR", "SIGSYS", "SIGRTMIN", "SIGRTMIN+1", "SIGRTMIN+2", "SIGRTMIN+3",
    "SIGRTMIN+4", "SIGRTMIN+5", "SIGRTMIN+6", "SIGRTMIN+7", "SIGRTMIN+8",
    "SIGRTMIN+9", "SIGRTMIN+10", "SIGRTMIN+11", "SIGRTMIN+12", "SIGRTMIN+13",
    "SIGRTMIN+14", "SIGRTMIN+15", "SIGRTMAX-14", "SIGRTMAX-13", "SIGRTMAX-12",
    "SIGRTMAX-11", "SIGRTMAX-10", "SIGRTMAX-9", "SIGRTMAX-8", "SIGRTMAX-7",
    "SIGRTMAX-6", "SIGRTMAX-5", "SIGRTMAX-4", "SIGRTMAX-3", "SIGRTMAX-2",
    "SIGRTMAX-1", "SIGRTMAX"
};

static const int signals_values[] = {
    SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGTRAP, SIGABRT, SIGBUS,
    SIGFPE, SIGKILL, SIGUSR1, SIGSEGV, SIGUSR2, SIGPIPE, SIGALRM,
    SIGTERM, SIGSTKFLT, SIGCHLD, SIGCONT, SIGSTOP, SIGTSTP, SIGTTIN,
    SIGTTOU, SIGURG, SIGXCPU, SIGXFSZ, SIGVTALRM, SIGPROF, SIGWINCH,
    SIGIO, SIGPWR, SIGSYS, SIGRTMIN_VAL, SIGRTMIN_VAL+1, SIGRTMIN_VAL+2, SIGRTMIN_VAL+3,
    SIGRTMIN_VAL+4, SIGRTMIN_VAL+5, SIGRTMIN_VAL+6, SIGRTMIN_VAL+7, SIGRTMIN_VAL+8,
    SIGRTMIN_VAL+9, SIGRTMIN_VAL+10, SIGRTMIN_VAL+11, SIGRTMIN_VAL+12, SIGRTMIN_VAL+13,
    SIGRTMIN_VAL+14, SIGRTMIN_VAL+15, SIGRTMAX_VAL-14, SIGRTMAX_VAL-13, SIGRTMAX_VAL-12,
    SIGRTMAX_VAL-11, SIGRTMAX_VAL-10, SIGRTMAX_VAL-9, SIGRTMAX_VAL-8, SIGRTMAX_VAL-7,
    SIGRTMAX_VAL-6, SIGRTMAX_VAL-5, SIGRTMAX_VAL-4, SIGRTMAX_VAL-3, SIGRTMAX_VAL-2,
    SIGRTMAX_VAL-1, SIGRTMAX_VAL
};

void print_signal(int sig) {
    for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); i++) {
        if (sig == signals_values[i]) {
            printf("%s", signals[i]);
            return;
        }
    }
    printf("%d", sig);
}

static const char *wait_options[] = {
    "WNOHANG", "WUNTRACED", "WCONTINUED"
};

static const int wait_options_values[] = {
    WNOHANG, WUNTRACED, WCONTINUED
};

void print_wait_options(int options) {
    bool first = true;
    printf("0x%x", options);
    for (size_t i = 0; i < sizeof(wait_options) / sizeof(wait_options[0]); i++) {
        if (options & wait_options_values[i]) {
            printf("%s%s", first ? " (" : "|", wait_options[i]);
            first = false;
        }
    }
    if (!first)
        printf(")");
}

static const char *clone_flags[] = {
    "CLONE_VM", "CLONE_FS", "CLONE_FILES", "CLONE_SIGHAND", "CLONE_PIDFD",
    "CLONE_PTRACE", "CLONE_VFORK", "CLONE_PARENT", "CLONE_THREAD", "CLONE_NEWNS",
    "CLONE_SYSVSEM", "CLONE_SETTLS", "CLONE_PARENT_SETTID", "CLONE_CHILD_CLEARTID",
    "CLONE_DETACHED", "CLONE_UNTRACED", "CLONE_CHILD_SETTID", "CLONE_NEWCGROUP",
    "CLONE_NEWUTS", "CLONE_NEWIPC", "CLONE_NEWUSER", "CLONE_NEWPID", "CLONE_NEWNET",
    "CLONE_IO"
};

static const unsigned long clone_flags_values[] = {
    CLONE_VM, CLONE_FS, CLONE_FILES, CLONE_SIGHAND, CLONE_PIDFD,
    CLONE_PTRACE, CLONE_VFORK, CLONE_PARENT, CLONE_THREAD, CLONE_NEWNS,
    CLONE_SYSVSEM, CLONE_SETTLS, CLONE_PARENT_SETTID, CLONE_CHILD_CLEARTID,
    CLONE_DETACHED, CLONE_UNTRACED, CLONE_CHILD_SETTID, CLONE_NEWCGROUP,
    CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWUSER, CLONE_NEWPID, CLONE_NEWNET,
    CLONE_IO
};

void print_clone_flags(unsigned long flags) {
    bool first = true;
    printf("0x%lx", flags);
    for (size_t i = 0; i < sizeof(clone_flags) / sizeof(clone_flags[0]); i++) {
        if (flags & clone_flags_values[i]) {
            printf("%s%s", first ? " (" : "|", clone_flags[i]);
            first = false;
        }
    }
    if (!first)
        printf(")");
}

void print_addr(void *addr) {
    if (addr == NULL)
        printf("NULL");
    else
        printf("%p", addr);
}

void print_str(pid_t pid, void *addr) {
    if (addr == NULL) {
        printf("NULL");
        return;
    }

    char buf[4096];
    long word;
    size_t i = 0;

    while (i < sizeof(buf) - 1) {
        word = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
        if (word == -1 && errno) {
            printf("%p", addr);
            return;
        }

        for (size_t j = 0; j < sizeof(word); j++) {
            char c = ((char *)&word)[j];
            if (c == '\0') {
                buf[i + j] = '\0';
                printf("\"%s\"", buf);
                return;
            }
            if (!isprint(c)) {
                printf("%p", addr);
                return;
            }
            buf[i + j] = c;
        }
        i += sizeof(word);
    }
    printf("%p", addr);
}

// Fonction de conversion de t_syscall vers t_syscall_ext
static t_syscall_ext convert_syscall(t_syscall syscall) {
    t_syscall_ext ext;
    ext.name = syscall.name;
    ext.nb_args = 0;
    
    // Compter le nombre d'arguments non-NONE
    for (int i = 0; i < MAX_ARGS; i++) {
        if (syscall.type_arg[i] != T_NONE) {
            ext.nb_args++;
        }
    }
    
    // Convertir les types d'arguments
    for (int i = 0; i < ext.nb_args; i++) {
        switch (syscall.type_arg[i]) {
            case T_INT:
            case T_CHAR:
            case T_SHORT:
                ext.args[i] = ARG_INT;
                break;
            case T_UINT:
            case T_UCHAR:
            case T_USHORT:
                ext.args[i] = ARG_UINT;
                break;
            case T_LINT:
                ext.args[i] = ARG_LONG;
                break;
            case T_ULINT:
                ext.args[i] = ARG_ULONG;
                break;
            case T_ADDR:
            case T_HEX:
            case T_BUFF:
                ext.args[i] = ARG_PTR;
                break;
            case T_STR:
                ext.args[i] = ARG_STR;
                break;
            default:
                ext.args[i] = ARG_INT;
                break;
        }
    }
    
    // Déterminer le type de retour
    switch (syscall.ret) {
        case T_INT:
        case T_CHAR:
        case T_SHORT:
        case T_UCHAR:
        case T_USHORT:
        case T_UINT:
            ext.ret_type = TYPE_INT;
            break;
        case T_ADDR:
        case T_HEX:
        case T_BUFF:
            ext.ret_type = TYPE_PTR;
            break;
        default:
            ext.ret_type = TYPE_INT;
            break;
    }
    
    return ext;
}

void print_syscall(pid_t child_pid, t_syscall syscall, ...) {
    va_list args;
    va_start(args, syscall);
    
    t_syscall_ext ext = convert_syscall(syscall);

    printf("%s(", ext.name);

    for (size_t i = 0; i < ext.nb_args; i++) {
        if (i > 0)
            printf(", ");

        switch (ext.args[i]) {
            case ARG_INT:
                printf("%d", va_arg(args, int));
                break;
            case ARG_UINT:
                printf("%u", va_arg(args, unsigned int));
                break;
            case ARG_LONG:
                printf("%ld", va_arg(args, long));
                break;
            case ARG_ULONG:
                printf("%lu", va_arg(args, unsigned long));
                break;
            case ARG_PTR:
                print_addr(va_arg(args, void *));
                break;
            case ARG_STR:
                print_str(child_pid, va_arg(args, void *));
                break;
            case ARG_OPEN_FLAGS:
                print_open_flags(va_arg(args, int));
                break;
            case ARG_MODE_T:
                print_mode_t(va_arg(args, unsigned int));
                break;
            case ARG_MMAP_PROT:
                print_mmap_prot(va_arg(args, int));
                break;
            case ARG_MMAP_FLAGS:
                print_mmap_flags(va_arg(args, int));
                break;
            case ARG_SIGNAL:
                print_signal(va_arg(args, int));
                break;
            case ARG_WAIT_OPTIONS:
                print_wait_options(va_arg(args, int));
                break;
            case ARG_CLONE_FLAGS:
                print_clone_flags(va_arg(args, unsigned long));
                break;
        }
    }

    printf(")");
    va_end(args);
}

void print_ret(long ret, enum e_type_syscall type) {
    if (ret < 0) {
        printf(" = -1 %s (%s)\n", strerror(-ret), errno == EINTR ? "EINTR" : "");
        return;
    }

    // Convertir le type de retour
    enum e_ret_type ret_type;
    switch (type) {
        case T_INT:
        case T_CHAR:
        case T_SHORT:
        case T_UCHAR:
        case T_USHORT:
        case T_UINT:
            ret_type = TYPE_INT;
            break;
        case T_ADDR:
        case T_HEX:
        case T_BUFF:
            ret_type = TYPE_PTR;
            break;
        default:
            ret_type = TYPE_INT;
            break;
    }

    switch (ret_type) {
        case TYPE_VOID:
            printf(" = ?\n");
            break;
        case TYPE_INT:
            printf(" = %d\n", (int)ret);
            break;
        case TYPE_PID_T:
            printf(" = %d\n", (pid_t)ret);
            break;
        case TYPE_SSIZE_T:
            printf(" = %ld\n", (long)ret);
            break;
        case TYPE_PTR:
            if (ret == 0)
                printf(" = NULL\n");
            else
                printf(" = %p\n", (void *)ret);
            break;
        default:
            printf(" = %ld\n", ret);
            break;
    }
} 