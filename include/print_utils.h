#ifndef FT_STRACE_PRINT_UTILS_H
#define FT_STRACE_PRINT_UTILS_H

#include <stdbool.h>
#include <stdarg.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/wait.h>
#include <sched.h>
#include <sys/uio.h>
#include <string.h>
#include <errno.h>
#include "ft_strace.h"

// Fonctions d'affichage des constantes
void print_open_flags(int flags);
void print_mode_t(unsigned int mode);
void print_mmap_prot(int prot);
void print_mmap_flags(int flags);
void print_signal(int sig);
void print_wait_options(int options);
void print_clone_flags(unsigned long flags);

// Fonctions d'affichage des appels système
void print_addr(void *addr);
void print_str(pid_t pid, void *addr);
void print_syscall(pid_t child_pid, t_syscall syscall, ...);
void print_ret(long ret, enum e_type_syscall type);

#endif //FT_STRACE_PRINT_UTILS_H 