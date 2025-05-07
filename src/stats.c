#include "strace.h"
#include <time.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static const t_syscall syscall_tab_x86_64[] = {
    #include "syscall_x86_tables.h"
};

static const t_syscall syscall_tab_i386[] = {
    #include "syscall_i386_tables.h"
};

typedef struct {
    int syscall_num;
    double percentage;
} t_syscall_sort;

static int compare_syscalls(const void *a, const void *b) {
    const t_syscall_sort *sa = (const t_syscall_sort *)a;
    const t_syscall_sort *sb = (const t_syscall_sort *)b;
    
    if (sa->percentage > sb->percentage) return -1;
    if (sa->percentage < sb->percentage) return 1;
    return 0;
}

void update_stats(t_strace_config *config, int syscall_num, long ret) {
    if (!config || syscall_num < 0 || syscall_num >= SYSCALL_NBR)
        return;

    if (config->stats[syscall_num].count == 0) {
        config->stats[syscall_num].time_spent = 0.0;
    }
    config->stats[syscall_num].count++;
    if (ret < 0)
        config->stats[syscall_num].errors++;
}

static void print_syscall_line(const char *name, unsigned long long count, 
                             unsigned long long errors, double time_spent, 
                             double total_time) {
    double percentage = 0.0;
    if (total_time > 0.0) {
        percentage = (time_spent / total_time) * 100.0;
    }
    double usecs_per_call = 0.0;
    if (count > 0) {
        usecs_per_call = time_spent * 1000000.0 / count;
    }
    
    fprintf(stderr, "%6.2f %11.6f %11.0f %9llu %9llu %s\n",
            percentage,
            time_spent,
            usecs_per_call,
            count,
            errors,
            name);
}

void print_summary(t_strace_config *config) {
    if (!config)
        return;

    unsigned long long total_calls = 0;
    unsigned long long total_errors = 0;
    double total_time = 0.0;
    int syscall_count = 0;
    t_syscall_sort sorted_syscalls[SYSCALL_NBR];

    for (int i = 0; i < SYSCALL_NBR; i++) {
        if (config->stats[i].count > 0) {
            total_calls += config->stats[i].count;
            total_errors += config->stats[i].errors;
            total_time += config->stats[i].time_spent;
            syscall_count++;
        }
    }

    int idx = 0;
    for (int i = 0; i < SYSCALL_NBR; i++) {
        if (config->stats[i].count > 0) {
            sorted_syscalls[idx].syscall_num = i;
            sorted_syscalls[idx].percentage = (config->stats[i].time_spent / total_time) * 100.0;
            idx++;
        }
    }

    qsort(sorted_syscalls, syscall_count, sizeof(t_syscall_sort), compare_syscalls);

    fprintf(stderr, "\n%% time     seconds  usecs/call     calls    errors syscall\n");
    fprintf(stderr, "------ ----------- ----------- --------- --------- ----------------\n");

    for (int i = 0; i < syscall_count; i++) {
        int syscall_num = sorted_syscalls[i].syscall_num;
        const char *syscall_name = NULL;
        
        if (config->stats[syscall_num].is_32bit) {
            if (syscall_num < (int)(sizeof(syscall_tab_i386) / sizeof(t_syscall))) {
                syscall_name = syscall_tab_i386[syscall_num].name;
            }
        } else {
            if (syscall_num < (int)(sizeof(syscall_tab_x86_64) / sizeof(t_syscall))) {
                syscall_name = syscall_tab_x86_64[syscall_num].name;
            }
        }
        if (!syscall_name) {
            syscall_name = "unknown";
        }
        print_syscall_line(syscall_name, 
                         config->stats[syscall_num].count,
                         config->stats[syscall_num].errors,
                         config->stats[syscall_num].time_spent,
                         total_time);
    }

    fprintf(stderr, "------ ----------- ----------- --------- --------- ----------------\n");
    print_syscall_line("total", total_calls, total_errors, total_time, total_time);
}

const char *resolve_path(const char *path) {
    if (!path)
        return NULL;

    static char resolved[PATH_MAX];
    if (realpath(path, resolved) == NULL)
        return path;
    return resolved;
} 