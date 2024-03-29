
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <elf.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <stdarg.h>
#include "include/syscall.h"
#include <stdbool.h>
#include <string.h>
#include <sys/uio.h>



// PTRACE_SYSCALL      continue to next syscall
// PTRACE_GETREGSET    read the trace register addr specifies
// PTRACE_SETOPTIONS
// PTRACE_GETSIGINFO   get signal information
// PTRACE_SEIZE        attach to a process
// PTRACE_INTERRUPT    interrupt process
// PTRACE_LISTEN       restart the stopped tracee

void print_addr(void *addr){
    if (addr == NULL)
        fprintf(stderr,"NULL");
    else
        fprintf(stderr,"%p", addr);
}

void escape(unsigned char *buff, int len){
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

void print_str(pid_t pid, void *addr){
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

void print_ret(long ret, t_syscall syscall){
    if (syscall.ret == T_INT)
        fprintf(stderr," = %ld\n", ret);
    else
        fprintf(stderr," = %#lx\n", ret);
}

void handle_syscall(pid_t child_pid, t_handle *handler){

    static t_syscall syscall_tab_x86[] = {
        #include "syscall_x86_tables.h"
    };
    static t_syscall syscall_tab_x86_64[] = {
        #include "syscall_i386_tables.h"
    };
    struct iovec x86_io;
    union {
        struct user_regs_struct reg;
        struct i386_user_regs_struct i386_reg;
    } regs;

    x86_io.iov_base = &regs;
    x86_io.iov_len = sizeof(regs);

    ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &x86_io);
    if (x86_io.iov_len != sizeof(struct i386_user_regs_struct)){
        if (regs.reg.orig_rax == 59) {
            handler->start = true;
        }
        if (handler->start) {
            if (!handler->result) {
                print_syscall(child_pid,
                  syscall_tab_x86[regs.reg.orig_rax],
                  regs.reg.rdi, regs.reg.rsi, regs.reg.rdx, regs.reg.r10, regs.reg.r8, regs.reg.r9);
                handler->result = true;
            } else {
                print_ret(regs.reg.rax, syscall_tab_x86[regs.reg.orig_rax]);
                handler->result = false;
            }
        }
    }
    else {
        if (regs.i386_reg.orig_eax == 11){
            handler->start = true;
        }
        if (handler->start){
            if (!handler->result){
                print_syscall(child_pid,
                  syscall_tab_x86[regs.i386_reg.orig_eax],
                  regs.i386_reg.ebx, regs.i386_reg.ecx, regs.i386_reg.edx, regs.i386_reg.esi, regs.i386_reg.edi, regs.i386_reg.ebp);
                handler->result = true;
            }
            else{
                print_ret(regs.i386_reg.eax, syscall_tab_x86[regs.i386_reg.orig_eax]);
                handler->result = false;
            }
        }

    }
}

void get_syscall(pid_t child_pid){
    int wait_status;
    int signal;
    t_handle handler = {false, false};

    fprintf(stderr, "[+]\tget_syscall\n");
    while(1){
        ptrace(PTRACE_SYSCALL, child_pid, 0, signal);

        fprintf(stderr, "[+]\twaitpid => %d\n", child_pid);
        waitpid(child_pid, &wait_status, 0);
        fprintf(stderr, "[+]\twaitpid 2\n");
        if (WIFEXITED(wait_status))
            break;

        siginfo_t sig;
        if (handler.start && !ptrace(PTRACE_GETSIGINFO, child_pid, NULL, &sig)
            && sig.si_signo != SIGTRAP){
            signal = sig.si_signo;
            fprintf(stderr, "SIGNAL => %d\n", signal);
        }
        else
            signal = 0;

        handle_syscall(child_pid, &handler);

    }
}

void block_signals(){
    sigset_t set;

    sigemptyset(&set);
    sigprocmask(SIG_SETMASK, &set, NULL);
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGQUIT);
    sigaddset(&set, SIGPIPE);
    sigaddset(&set, SIGTERM);
    sigprocmask(SIG_BLOCK, &set, NULL);
    fprintf(stderr, "[+]\tblock signals\n");
}

void attach_process(pid_t child_pid){
    fprintf(stderr, "[+]\tatach to process\n");
    if (ptrace(PTRACE_SEIZE, child_pid, NULL, NULL) < 0
        || ptrace(PTRACE_INTERRUPT, child_pid, NULL, NULL) < 0)
        perror("error with ptrace\n");

    int wait_status;
    fprintf(stderr, "[+]\twait pid d => %d\n", child_pid);
    waitpid(child_pid, &wait_status, 0);
    fprintf(stderr, "[+]\twait pid 2\n");
    if (WIFSTOPPED(wait_status)) {
        fprintf(stderr, "[+]\tProcess %d stopped, signal %d\n", child_pid, WSTOPSIG(wait_status));
    }
}

int main(int argc, char **argv, char **envp){
	pid_t child_pid;

	child_pid = fork();
	if (child_pid == 0){
        raise(SIGSTOP);
        if (execve(argv[1], argv+1, envp) < 0) {
            perror("error with execve\n");
        }
        fprintf(stderr, "error with exec \n");
		return (0);
	}
    attach_process(child_pid);
    block_signals();
    get_syscall(child_pid);

    fprintf(stderr, "\nFINISH EXEC\n");
	return (0);
}