#include "strace.h"

void handle_syscall(pid_t child_pid, t_handle *handler){
    static const t_syscall syscall_tab_x86_64[] = {
        #include "syscall_x86_tables.h"
    };
    static const t_syscall syscall_tab_i386[] = {
        #include "syscall_i386_tables.h"
    };
    static const unsigned long long int max_syscall_tab_x86_64 = (unsigned long long int)(sizeof(syscall_tab_x86_64) / sizeof(t_syscall));
    static const int max_syscall_tab_i386 = (int)(sizeof(syscall_tab_i386) / sizeof(t_syscall));

    struct iovec x86_io;
    union {
        struct user_regs_struct reg;
        struct i386_user_regs_struct i386_reg;
    } regs;

    x86_io.iov_base = &regs;
    x86_io.iov_len = sizeof(regs);

    if (ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &x86_io) < 0)
        return ;
    if (x86_io.iov_len == sizeof(struct i386_user_regs_struct)){
        if (regs.i386_reg.orig_eax == 11){
            handler->start = true;
        }
        if (handler->start){
            if (!handler->result && regs.i386_reg.orig_eax < max_syscall_tab_i386 && regs.i386_reg.eax == -ENOSYS){
                print_syscall(child_pid,
                              syscall_tab_i386[regs.i386_reg.orig_eax],
                              regs.i386_reg.ebx, regs.i386_reg.ecx, regs.i386_reg.edx, regs.i386_reg.esi, regs.i386_reg.edi, regs.i386_reg.ebp);
                handler->result = true;
            }
            else if (handler->result){
                if (regs.i386_reg.orig_eax >= 0 && regs.i386_reg.orig_eax < max_syscall_tab_i386)
                    print_ret(regs.i386_reg.eax, syscall_tab_i386[regs.i386_reg.orig_eax].ret);
                else
                    print_ret(regs.i386_reg.eax, T_INT);
                handler->result = false;
                if (regs.i386_reg.orig_eax == 11){
                    fprintf(stderr, "[ Process PID=%d runs in 32 bit mode. ]\n", child_pid);
                }
            }
        }
    }
    else {
        if (regs.reg.orig_rax == 59) {
            handler->start = true;
        }
        if (handler->start) {
            if (!handler->result && regs.reg.orig_rax < max_syscall_tab_x86_64 && regs.reg.rax == (unsigned long long int)-ENOSYS) {
                print_syscall(child_pid,
                              syscall_tab_x86_64[regs.reg.orig_rax],
                              regs.reg.rdi, regs.reg.rsi, regs.reg.rdx, regs.reg.r10, regs.reg.r8, regs.reg.r9);
                handler->result = true;
            } else if (handler->result){
                if (regs.reg.orig_rax < max_syscall_tab_x86_64)
                    print_ret(regs.reg.rax, syscall_tab_x86_64[regs.reg.orig_rax].ret);
                else
                    print_ret(regs.reg.rax, T_INT);
                handler->result = false;
            }
        }
    }
}

int get_syscall(pid_t child_pid){
    int wait_status;
    int signal;
    t_handle handler = {false, false};

    signal = 0;
    while(42){
        if (ptrace(PTRACE_SYSCALL, child_pid, 0, signal) < 0
            || wait_signal(child_pid, &wait_status) < 0)
            break;
        siginfo_t sig;
        if (handler.start && !ptrace(PTRACE_GETSIGINFO, child_pid, NULL, &sig)
            && sig.si_signo != SIGTRAP){
            signal = sig.si_signo;
            fprintf(stderr, "--- %s ---\n", signame(signal));
            //continue;
        }
        else
            signal = 0;
        handle_syscall(child_pid, &handler);
    }
    if (handler.start && handler.result)
        fprintf(stderr," = ?\n");
    return wait_status;
}

void attach_process(pid_t child_pid){
    if (ptrace(PTRACE_SEIZE, child_pid, NULL, NULL) < 0)
        perror("error with ptrace 1\n");

    wait_signal(child_pid, NULL);

    if (ptrace(PTRACE_SETOPTIONS, child_pid, NULL, PTRACE_O_TRACESYSGOOD))
        perror("error with ptrace 2\n");

    if (ptrace(PTRACE_INTERRUPT, child_pid, NULL, NULL) < 0)
        perror("error with ptrace 3\n");


}

int strace(const char *exec, char **argv, char **envp){
    raise(SIGSTOP);
    execve(exec, argv+1, envp);
    fprintf(stderr, "ft_strace: Can't execve '%s': %s\n", argv[1], strerror(errno));
    return (EXIT_FAILURE);
}

int main(int argc, char **argv, char **envp){
    const char *file_exec;
	pid_t child_pid;

    if (argc < 2){
        fprintf(stderr, "ft_strace: must PROG [ARG]\n"); return (EXIT_FAILURE);
    }

    file_exec = get_file_exec(argv[1]);
    if (file_exec == NULL) {
        fprintf(stderr, "ft_strace: Can't stat '%s': %s\n", argv[1], strerror(errno)); return (EXIT_FAILURE);
    }

    child_pid = fork();
    if (child_pid < 0){
        perror("error with fork\n"); return (EXIT_FAILURE);
    }

	if (child_pid == 0)
        return (strace(file_exec, argv, envp));
    attach_process(child_pid);

    int status = get_syscall(child_pid);
    if (WIFEXITED(status)){
        fprintf(stderr, "+++ exited with %d +++\n", WEXITSTATUS(status));
    }
    else if (WIFSIGNALED(status)){
        fprintf(stderr, "+++ killed by %s +++\n", strsignal(WTERMSIG(status)));
        kill(getpid(), WTERMSIG(status));
    }
	return (EXIT_SUCCESS);
}