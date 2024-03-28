#ifndef FT_STRACE_SYSCALL_H
#define FT_STRACE_SYSCALL_H

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

    T_CADDR_T,
    T_SIGHANDLER_T,
    T_E_PTRACE_REQUEST,

    T_NONE
};

typedef struct syscall_s {
    char *name;
    enum e_type_syscall type_arg[MAX_ARGS];
    enum e_type_syscall ret;
} t_syscall;


struct i386_user_regs_struct
{
    long int ebx;
    long int ecx;
    long int edx;
    long int esi;
    long int edi;
    long int ebp;
    long int eax;
    long int xds;
    long int xes;
    long int xfs;
    long int xgs;
    long int orig_eax;
    long int eip;
    long int xcs;
    long int eflags;
    long int esp;
    long int xss;
};

#endif //FT_STRACE_SYSCALL_H
