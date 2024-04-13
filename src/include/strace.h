#ifndef FT_STRACE_STRACE_H
#define FT_STRACE_STRACE_H

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
#include <stdbool.h>
#include <string.h>
#include <sys/uio.h>
#include <signal.h>
#include <sys/stat.h>
#include <errno.h>

#include "syscall.h"

void print_syscall(pid_t child_pid, t_syscall syscall, ...);
void print_ret(long ret, enum e_type_syscall syscall);
int wait_signal(pid_t child_pid, int *status);
const char *signame(int signal);
const char *get_file_exec(char *prog_name);

#endif //FT_STRACE_STRACE_H
