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

#define SYSCALL_NBR 386

typedef struct {
    unsigned long long count;
    unsigned long long errors;
    double time_spent;
    bool is_32bit;
} t_syscall_stats;

typedef struct {
    t_syscall_stats stats[SYSCALL_NBR];
    bool summary_mode;
    bool path_mode;
} t_strace_config;

void print_syscall(pid_t child_pid, t_syscall syscall, ...);
void print_ret(long ret, enum e_type_syscall syscall);
int wait_signal(pid_t child_pid, int *status);
const char *signame(int signal);
const char *get_file_exec(char *prog_name);
void print_summary(t_strace_config *config);
void update_stats(t_strace_config *config, int syscall_num, long ret);
const char *resolve_path(const char *path);

#endif //FT_STRACE_STRACE_H
