#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>

// PTRACE_SYSCALL
// PTRACE_GETREGSET
// PTRACE_SETOPTIONS
// PTRACE_GETSIGINFO
// PTRACE_SEIZE
// PTRACE_INTERRUPT
// PTRACE_LISTEN

int main(int argc, char **argv){
	pid_t child_pid;

	child_pid = fork();
	if (child_pid == 0){
        raise(SIGSTOP);
		execvp(argv[1], argv+1);
		return (0);
	}

    ptrace(PTRACE_SEIZE, child_pid, NULL, NULL);
    ptrace(PTRACE_INTERRUPT, child_pid, NULL, NULL);

    int wait_status;

    waitpid(child_pid, &wait_status, 0);


    if (WIFSTOPPED(wait_status)) {
        printf("Process %d stopped, signal %d\n", child_pid, WSTOPSIG(wait_status));
    }

    ptrace(PTRACE_SYSCALL, child_pid, 0, 0);

	return (0);
}