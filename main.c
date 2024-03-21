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
		ptrace(PTRACE_SEIZE)
		execvp(argv[1], argv+1);
		return (0);
	}
	wait(NULL);

	return (0);
}