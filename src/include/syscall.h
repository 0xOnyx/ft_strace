#ifndef FT_STRACE_SYSCALL_H
#define FT_STRACE_SYSCALL_H

#include <stdbool.h>

#define MAX_ARGS 6

enum e_type_syscall {
    T_CHAR,
    T_SHORT,
    T_INT,
    T_LINT,
    T_LLINT,
    T_UCHAR,
    T_USHORT,
    T_UINT,
    T_ULINT,
    T_ULLINT,
    T_FLOAT,
    T_DOUBLE,
    T_LDOUBLE,
    T_ADDR,
    T_HEX,
    T_BUFF,
    T_STR,
    T_UNKNOWN,

    T_NONE
};

typedef struct syscall_s {
    char *name;
    enum e_type_syscall type_arg[MAX_ARGS];
    enum e_type_syscall ret;
} t_syscall;

typedef struct handle_s {
    bool start;
    bool result;
} t_handle;

struct i386_user_regs_struct
{
    int ebx;
    int ecx;
    int edx;
    int esi;
    int edi;
    int ebp;
    int eax;
    int xds;
    int xes;
    int xfs;
    int xgs;
    int orig_eax;
    int eip;
    int xcs;
    int eflags;
    int esp;
    int xss;
};

#endif //FT_STRACE_SYSCALL_H
