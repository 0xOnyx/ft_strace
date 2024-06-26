[  0] = {"read", {T_INT, T_BUFF, T_ULINT, T_NONE, T_NONE, T_NONE}, T_LINT},
[  1] = {"write", {T_INT, T_STR, T_ULINT, T_NONE, T_NONE, T_NONE}, T_LINT},
[  2] = {"open", {T_STR, T_INT, T_UINT, T_NONE, T_NONE, T_NONE}, T_INT},
[  3] = {"close", {T_INT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[  4] = {"stat", {T_STR, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[  5] = {"fstat", {T_INT, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[  6] = {"lstat", {T_STR, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[  7] = {"poll", {T_ADDR, T_ULINT, T_INT, T_NONE, T_NONE, T_NONE}, T_INT},
[  8] = {"lseek", {T_INT, T_LINT, T_INT, T_NONE, T_NONE, T_NONE}, T_LINT},
[  9] = {"mmap", {T_ADDR, T_ULINT, T_INT, T_INT, T_INT, T_LINT}, T_ADDR},
[ 10] = {"mprotect", {T_ADDR, T_ULINT, T_INT, T_NONE, T_NONE, T_NONE}, T_INT},
[ 11] = {"munmap", {T_ADDR, T_ULINT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 12] = {"brk", {T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_HEX},
[ 13] = {"rt_sigaction", {T_INT, T_ADDR, T_ADDR, T_ULINT, T_NONE, T_NONE}, T_INT},
[ 14] = {"rt_sigprocmask", {T_INT, T_ADDR, T_ADDR, T_ULINT, T_NONE, T_NONE}, T_INT},
[ 15] = {"rt_sigreturn", {T_HEX, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 16] = {"ioctl", {T_INT, T_ULINT, T_HEX, T_NONE, T_NONE, T_NONE}, T_INT},
[ 17] = {"pread", {T_INT, T_ADDR, T_ULINT, T_LINT, T_NONE, T_NONE}, T_LINT},
[ 18] = {"pwrite", {T_INT, T_ADDR, T_ULINT, T_LINT, T_NONE, T_NONE}, T_LINT},
[ 19] = {"readv", {T_INT, T_ADDR, T_INT, T_NONE, T_NONE, T_NONE}, T_LINT},
[ 20] = {"writev", {T_INT, T_ADDR, T_INT, T_NONE, T_NONE, T_NONE}, T_LINT},
[ 21] = {"access", {T_STR, T_INT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 22] = {"pipe", {T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 23] = {"select", {T_INT, T_ADDR, T_ADDR, T_ADDR, T_ADDR, T_NONE}, T_INT},
[ 24] = {"sched_yield", {T_NONE, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 25] = {"mremap", {T_ADDR, T_ULINT, T_ULINT, T_HEX, T_NONE, T_NONE}, T_ADDR},
[ 26] = {"msync", {T_ADDR, T_ULINT, T_INT, T_NONE, T_NONE, T_NONE}, T_INT},
[ 27] = {"mincore", {T_ADDR, T_ULINT, T_ADDR, T_NONE, T_NONE, T_NONE}, T_INT},
[ 28] = {"madvise", {T_ADDR, T_ULINT, T_INT, T_NONE, T_NONE, T_NONE}, T_INT},
[ 29] = {"shmget", {T_UNKNOWN, T_ULINT, T_INT, T_NONE, T_NONE, T_NONE}, T_INT},
[ 30] = {"shmat", {T_INT, T_ADDR, T_INT, T_NONE, T_NONE, T_NONE}, T_ADDR},
[ 31] = {"shmctl", {T_INT, T_INT, T_ADDR, T_NONE, T_NONE, T_NONE}, T_INT},
[ 32] = {"dup", {T_INT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 33] = {"dup2", {T_INT, T_INT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 34] = {"pause", {T_NONE, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 35] = {"nanosleep", {T_ADDR, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 36] = {"getitimer", {T_INT, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 37] = {"alarm", {T_UINT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_UINT},
[ 38] = {"setitimer", {T_INT, T_ADDR, T_ADDR, T_NONE, T_NONE, T_NONE}, T_INT},
[ 39] = {"getpid", {T_NONE, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 40] = {"sendfile", {T_INT, T_INT, T_ADDR, T_ULINT, T_NONE, T_NONE}, T_LINT},
[ 41] = {"socket", {T_INT, T_INT, T_INT, T_NONE, T_NONE, T_NONE}, T_INT},
[ 42] = {"connect", {T_INT, T_ADDR, T_UINT, T_NONE, T_NONE, T_NONE}, T_INT},
[ 43] = {"accept", {T_INT, T_ADDR, T_ADDR, T_NONE, T_NONE, T_NONE}, T_INT},
[ 44] = {"sendto", {T_INT, T_ADDR, T_ULINT, T_INT, T_ADDR, T_UINT}, T_LINT},
[ 45] = {"recvfrom", {T_INT, T_ADDR, T_ULINT, T_INT, T_ADDR, T_ADDR}, T_LINT},
[ 46] = {"sendmsg", {T_INT, T_ADDR, T_INT, T_NONE, T_NONE, T_NONE}, T_LINT},
[ 47] = {"recvmsg", {T_INT, T_ADDR, T_INT, T_NONE, T_NONE, T_NONE}, T_LINT},
[ 48] = {"shutdown", {T_INT, T_INT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 49] = {"bind", {T_INT, T_ADDR, T_UINT, T_NONE, T_NONE, T_NONE}, T_INT},
[ 50] = {"listen", {T_INT, T_INT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 51] = {"getsockname", {T_INT, T_ADDR, T_ADDR, T_NONE, T_NONE, T_NONE}, T_INT},
[ 52] = {"getpeername", {T_INT, T_ADDR, T_ADDR, T_NONE, T_NONE, T_NONE}, T_INT},
[ 53] = {"socketpair", {T_INT, T_INT, T_INT, T_ADDR, T_NONE, T_NONE}, T_INT},
[ 54] = {"setsockopt", {T_INT, T_INT, T_INT, T_ADDR, T_UINT, T_NONE}, T_INT},
[ 55] = {"getsockopt", {T_INT, T_INT, T_INT, T_ADDR, T_ADDR, T_NONE}, T_INT},
[ 56] = {"clone", {T_ADDR, T_ADDR, T_INT, T_ADDR, T_NONE, T_NONE}, T_INT},
[ 57] = {"fork", {T_NONE, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 58] = {"vfork", {T_NONE, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 59] = {"execve", {T_STR, T_ADDR, T_ADDR, T_NONE, T_NONE, T_NONE}, T_INT},
[ 60] = {"exit", {T_INT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_NONE},
[ 61] = {"wait4", {T_INT, T_ADDR, T_INT, T_ADDR, T_NONE, T_NONE}, T_INT},
[ 62] = {"kill", {T_INT, T_INT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 63] = {"uname", {T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 64] = {"semget", {T_UNKNOWN, T_INT, T_INT, T_NONE, T_NONE, T_NONE}, T_INT},
[ 65] = {"semop", {T_INT, T_ADDR, T_ULINT, T_NONE, T_NONE, T_NONE}, T_INT},
[ 66] = {"semctl", {T_INT, T_INT, T_INT, T_HEX, T_NONE, T_NONE}, T_INT},
[ 67] = {"shmdt", {T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 68] = {"msgget", {T_UNKNOWN, T_INT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 69] = {"msgsnd", {T_INT, T_ADDR, T_ULINT, T_INT, T_NONE, T_NONE}, T_INT},
[ 70] = {"msgrcv", {T_INT, T_ADDR, T_ULINT, T_LINT, T_INT, T_NONE}, T_LINT},
[ 71] = {"msgctl", {T_INT, T_INT, T_ADDR, T_NONE, T_NONE, T_NONE}, T_INT},
[ 72] = {"fcntl", {T_INT, T_INT, T_HEX, T_NONE, T_NONE, T_NONE}, T_INT},
[ 73] = {"flock", {T_INT, T_INT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 74] = {"fsync", {T_INT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 75] = {"fdatasync", {T_INT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 76] = {"truncate", {T_STR, T_LINT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 77] = {"ftruncate", {T_INT, T_LINT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 78] = {"getdents", {T_UINT, T_ADDR, T_UINT, T_NONE, T_NONE, T_NONE}, T_INT},
[ 79] = {"getcwd", {T_STR, T_ULINT, T_NONE, T_NONE, T_NONE, T_NONE}, T_STR},
[ 80] = {"chdir", {T_STR, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 81] = {"fchdir", {T_INT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 82] = {"rename", {T_STR, T_STR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 83] = {"mkdir", {T_STR, T_UINT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 84] = {"rmdir", {T_STR, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 85] = {"creat", {T_STR, T_UINT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 86] = {"link", {T_STR, T_STR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 87] = {"unlink", {T_STR, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 88] = {"symlink", {T_STR, T_STR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 89] = {"readlink", {T_STR, T_STR, T_ULINT, T_NONE, T_NONE, T_NONE}, T_LINT},
[ 90] = {"chmod", {T_STR, T_UINT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 91] = {"fchmod", {T_INT, T_UINT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 92] = {"chown", {T_STR, T_UINT, T_UINT, T_NONE, T_NONE, T_NONE}, T_INT},
[ 93] = {"fchown", {T_INT, T_UINT, T_UINT, T_NONE, T_NONE, T_NONE}, T_INT},
[ 94] = {"lchown", {T_STR, T_UINT, T_UINT, T_NONE, T_NONE, T_NONE}, T_INT},
[ 95] = {"umask", {T_UINT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_UINT},
[ 96] = {"gettimeofday", {T_ADDR, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 97] = {"getrlimit", {T_INT, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 98] = {"getrusage", {T_INT, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[ 99] = {"sysinfo", {T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[100] = {"times", {T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_LINT},
[101] = {"ptrace", {T_INT, T_INT, T_ADDR, T_ADDR, T_NONE, T_NONE}, T_LINT},
[102] = {"getuid", {T_NONE, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_UINT},
[103] = {"syslog", {T_INT, T_STR, T_INT, T_NONE, T_NONE, T_NONE}, T_INT},
[104] = {"getgid", {T_NONE, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_UINT},
[105] = {"setuid", {T_UINT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[106] = {"setgid", {T_UINT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[107] = {"geteuid", {T_NONE, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_UINT},
[108] = {"getegid", {T_NONE, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_UINT},
[109] = {"setpgid", {T_INT, T_INT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[110] = {"getppid", {T_NONE, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[111] = {"getpgrp", {T_INT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[112] = {"setsid", {T_NONE, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[113] = {"setreuid", {T_UINT, T_UINT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[114] = {"setregid", {T_UINT, T_UINT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[115] = {"getgroups", {T_INT, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[116] = {"setgroups", {T_ULINT, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[117] = {"setresuid", {T_UINT, T_UINT, T_UINT, T_NONE, T_NONE, T_NONE}, T_INT},
[118] = {"getresuid", {T_ADDR, T_ADDR, T_ADDR, T_NONE, T_NONE, T_NONE}, T_INT},
[119] = {"setresgid", {T_UINT, T_UINT, T_UINT, T_NONE, T_NONE, T_NONE}, T_INT},
[120] = {"getresgid", {T_ADDR, T_ADDR, T_ADDR, T_NONE, T_NONE, T_NONE}, T_INT},
[121] = {"getpgid", {T_INT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[122] = {"setfsuid", {T_UINT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[123] = {"setfsgid", {T_UINT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[124] = {"getsid", {T_INT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[125] = {"capget", {T_HEX, T_HEX, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[126] = {"capset", {T_HEX, T_HEX, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[127] = {"rt_sigpending", {T_ADDR, T_ULINT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[128] = {"rt_sigtimedwait", {T_ADDR, T_ADDR, T_ADDR, T_NONE, T_NONE, T_NONE}, T_INT},
[129] = {"rt_sigqueueinfo", {T_INT, T_INT, T_ADDR, T_NONE, T_NONE, T_NONE}, T_INT},
[130] = {"rt_sigsuspend", {T_ADDR, T_ULINT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[131] = {"sigaltstack", {T_ADDR, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[132] = {"utime", {T_STR, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[133] = {"mknod", {T_STR, T_UINT, T_ULINT, T_NONE, T_NONE, T_NONE}, T_INT},
[134] = {"uselib", {T_STR, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[135] = {"personality", {T_ULINT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[136] = {"ustat", {T_ULINT, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[137] = {"statfs", {T_STR, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[138] = {"fstatfs", {T_INT, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[139] = {"sysfs", {T_INT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[140] = {"getpriority", {T_INT, T_UINT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[141] = {"setpriority", {T_INT, T_UINT, T_INT, T_NONE, T_NONE, T_NONE}, T_INT},
[142] = {"sched_setparam", {T_INT, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[143] = {"sched_getparam", {T_INT, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[144] = {"sched_setscheduler", {T_INT, T_INT, T_ADDR, T_NONE, T_NONE, T_NONE}, T_INT},
[145] = {"sched_getscheduler", {T_INT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[146] = {"sched_get_priority_max", {T_INT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[147] = {"sched_get_priority_min", {T_INT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[148] = {"sched_rr_get_interval", {T_INT, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[149] = {"mlock", {T_ADDR, T_ULINT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[150] = {"munlock", {T_ADDR, T_ULINT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[151] = {"mlockall", {T_INT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[152] = {"munlockall", {T_NONE, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[153] = {"vhangup", {T_NONE, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[154] = {"modify_ldt", {T_INT, T_ADDR, T_ULINT, T_NONE, T_NONE, T_NONE}, T_INT},
[155] = {"pivot_root", {T_STR, T_STR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[156] = {"_sysctl", {T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[157] = {"prctl", {T_INT, T_ULINT, T_ULINT, T_ULINT, T_ULINT, T_NONE}, T_INT},
[158] = {"arch_prctl", {T_INT, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[159] = {"adjtimex", {T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[160] = {"setrlimit", {T_INT, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[161] = {"chroot", {T_STR, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[162] = {"sync", {T_NONE, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_NONE},
[163] = {"acct", {T_STR, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[164] = {"settimeofday", {T_ADDR, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[165] = {"mount", {T_STR, T_STR, T_STR, T_ULINT, T_ADDR, T_NONE}, T_INT},
[166] = {"umount2", {T_STR, T_INT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[167] = {"swapon", {T_STR, T_INT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[168] = {"swapoff", {T_STR, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[169] = {"reboot", {T_INT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[170] = {"sethostname", {T_STR, T_ULINT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[171] = {"setdomainname", {T_STR, T_ULINT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[172] = {"iopl", {T_INT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[173] = {"ioperm", {T_ULINT, T_ULINT, T_INT, T_NONE, T_NONE, T_NONE}, T_INT},
[174] = {"create_module", {T_STR, T_ULINT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[175] = {"init_module", {T_ADDR, T_ULINT, T_STR, T_NONE, T_NONE, T_NONE}, T_INT},
[176] = {"delete_module", {T_STR, T_INT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[177] = {"get_kernel_syms", {T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[178] = {"query_module", {T_STR, T_INT, T_ADDR, T_ULINT, T_ADDR, T_NONE}, T_INT},
[179] = {"quotactl", {T_INT, T_STR, T_INT, T_INT, T_NONE, T_NONE}, T_INT},
[180] = {"nfsservctl", {T_INT, T_ADDR, T_ADDR, T_NONE, T_NONE, T_NONE}, T_LINT},
[181] = {"getpmsg", {T_NONE, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_LLINT},
[182] = {"putpmsg", {T_NONE, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_LLINT},
[183] = {"afs_syscall", {T_NONE, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_LLINT},
[184] = {"tuxcall", {T_NONE, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_LLINT},
[185] = {"security", {T_NONE, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_LLINT},
[186] = {"gettid", {T_NONE, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[187] = {"readahead", {T_INT, T_LINT, T_ULINT, T_NONE, T_NONE, T_NONE}, T_LINT},
[188] = {"setxattr", {T_STR, T_STR, T_ADDR, T_ULINT, T_INT, T_NONE}, T_INT},
[189] = {"lsetxattr", {T_STR, T_STR, T_ADDR, T_ULINT, T_INT, T_NONE}, T_INT},
[190] = {"fsetxattr", {T_INT, T_STR, T_ADDR, T_ULINT, T_INT, T_NONE}, T_INT},
[191] = {"getxattr", {T_STR, T_STR, T_ADDR, T_ULINT, T_NONE, T_NONE}, T_LINT},
[192] = {"lgetxattr", {T_STR, T_STR, T_ADDR, T_ULINT, T_NONE, T_NONE}, T_LINT},
[193] = {"fgetxattr", {T_INT, T_STR, T_ADDR, T_ULINT, T_NONE, T_NONE}, T_LINT},
[194] = {"listxattr", {T_STR, T_STR, T_ULINT, T_NONE, T_NONE, T_NONE}, T_LINT},
[195] = {"llistxattr", {T_STR, T_STR, T_ULINT, T_NONE, T_NONE, T_NONE}, T_LINT},
[196] = {"flistxattr", {T_INT, T_STR, T_ULINT, T_NONE, T_NONE, T_NONE}, T_LINT},
[197] = {"removexattr", {T_STR, T_STR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[198] = {"lremovexattr", {T_STR, T_STR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[199] = {"fremovexattr", {T_INT, T_STR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[200] = {"tkill", {T_INT, T_INT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[201] = {"time", {T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_LINT},
[202] = {"futex", {T_ADDR, T_INT, T_INT, T_ADDR, T_ADDR, T_INT}, T_INT},
[203] = {"sched_setaffinity", {T_INT, T_ULINT, T_ADDR, T_NONE, T_NONE, T_NONE}, T_INT},
[204] = {"sched_getaffinity", {T_INT, T_ULINT, T_ADDR, T_NONE, T_NONE, T_NONE}, T_INT},
[205] = {"set_thread_area", {T_ULINT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[206] = {"io_setup", {T_UINT, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[207] = {"io_destroy", {T_ULINT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[208] = {"io_getevents", {T_ULINT, T_LINT, T_LINT, T_ADDR, T_ADDR, T_NONE}, T_INT},
[209] = {"io_submit", {T_ULINT, T_LINT, T_ADDR, T_NONE, T_NONE, T_NONE}, T_INT},
[210] = {"io_cancel", {T_ULINT, T_ADDR, T_ADDR, T_NONE, T_NONE, T_NONE}, T_INT},
[211] = {"get_thread_area", {T_NONE, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[212] = {"lookup_dcookie", {T_ULLINT, T_STR, T_ULINT, T_NONE, T_NONE, T_NONE}, T_INT},
[213] = {"epoll_create", {T_INT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[214] = {"epoll_ctl_old", {T_HEX, T_HEX, T_HEX, T_ADDR, T_NONE, T_NONE}, T_INT},
[215] = {"epoll_wait_old", {T_HEX, T_ADDR, T_HEX, T_HEX, T_NONE, T_NONE}, T_INT},
[216] = {"remap_file_pages", {T_ADDR, T_ULINT, T_INT, T_ULINT, T_INT, T_NONE}, T_INT},
[217] = {"getdents", {T_UINT, T_ADDR, T_UINT, T_NONE, T_NONE, T_NONE}, T_INT},
[218] = {"set_tid_address", {T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_LINT},
[219] = {"restart_syscall", {T_NONE, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[220] = {"semtimedop", {T_INT, T_ADDR, T_ULINT, T_ADDR, T_NONE, T_NONE}, T_INT},
[221] = {"fadvise64", {T_INT, T_LINT, T_LINT, T_HEX, T_NONE, T_NONE}, T_INT},
[222] = {"timer_create", {T_INT, T_ADDR, T_ADDR, T_NONE, T_NONE, T_NONE}, T_INT},
[223] = {"timer_settime", {T_INT, T_INT, T_ADDR, T_ADDR, T_NONE, T_NONE}, T_INT},
[224] = {"timer_gettime", {T_INT, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[225] = {"timer_getoverrun", {T_INT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[226] = {"timer_delete", {T_INT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[227] = {"clock_settime", {T_INT, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[228] = {"clock_gettime", {T_INT, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[229] = {"clock_getres", {T_INT, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[230] = {"clock_nanosleep", {T_INT, T_INT, T_ADDR, T_ADDR, T_NONE, T_NONE}, T_INT},
[231] = {"exit_group", {T_INT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_NONE},
[232] = {"epoll_wait", {T_HEX, T_ADDR, T_HEX, T_HEX, T_NONE, T_NONE}, T_INT},
[233] = {"epoll_ctl", {T_HEX, T_HEX, T_HEX, T_ADDR, T_NONE, T_NONE}, T_INT},
[234] = {"tgkill", {T_INT, T_INT, T_INT, T_NONE, T_NONE, T_NONE}, T_INT},
[235] = {"utimes", {T_STR, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[236] = {"vserver", {T_NONE, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_LLINT},
[237] = {"mbind", {T_ADDR, T_ULINT, T_INT, T_ADDR, T_ULINT, T_UINT}, T_LINT},
[238] = {"set_mempolicy", {T_INT, T_ADDR, T_ULINT, T_NONE, T_NONE, T_NONE}, T_LINT},
[239] = {"get_mempolicy", {T_ADDR, T_ADDR, T_ULINT, T_ADDR, T_ULINT, T_NONE}, T_LINT},
[240] = {"mq_open", {T_STR, T_INT, T_UINT, T_ADDR, T_NONE, T_NONE}, T_INT},
[241] = {"mq_unlink", {T_STR, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[242] = {"mq_timedsend", {T_INT, T_STR, T_ULINT, T_UINT, T_ADDR, T_NONE}, T_INT},
[243] = {"mq_timedreceive", {T_INT, T_STR, T_ULINT, T_ADDR, T_ADDR, T_NONE}, T_LINT},
[244] = {"mq_notify", {T_INT, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[245] = {"mq_getsetattr", {T_INT, T_ADDR, T_ADDR, T_NONE, T_NONE, T_NONE}, T_INT},
[246] = {"kexec_load", {T_ULINT, T_ULINT, T_ADDR, T_ULINT, T_NONE, T_NONE}, T_LINT},
[247] = {"waitid", {T_UINT, T_UINT, T_ADDR, T_INT, T_NONE, T_NONE}, T_INT},
[248] = {"add_key", {T_STR, T_STR, T_ADDR, T_ULINT, T_INT, T_NONE}, T_INT},
[249] = {"request_key", {T_STR, T_STR, T_STR, T_INT, T_NONE, T_NONE}, T_INT},
[250] = {"keyctl", {T_HEX, T_HEX, T_HEX, T_HEX, T_HEX, T_NONE}, T_LINT},
[251] = {"ioprio_set", {T_INT, T_INT, T_INT, T_NONE, T_NONE, T_NONE}, T_INT},
[252] = {"ioprio_get", {T_INT, T_INT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[253] = {"inotify_init", {T_NONE, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[254] = {"inotify_add_watch", {T_INT, T_STR, T_UINT, T_NONE, T_NONE, T_NONE}, T_INT},
[255] = {"inotify_rm_watch", {T_INT, T_INT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[256] = {"migrate_pages", {T_INT, T_ULINT, T_ADDR, T_ADDR, T_NONE, T_NONE}, T_LINT},
[257] = {"openat", {T_INT, T_STR, T_INT, T_UINT, T_NONE, T_NONE}, T_INT},
[258] = {"mkdirat", {T_INT, T_STR, T_UINT, T_NONE, T_NONE, T_NONE}, T_INT},
[259] = {"mknodat", {T_INT, T_STR, T_UINT, T_ULINT, T_NONE, T_NONE}, T_INT},
[260] = {"fchownat", {T_INT, T_STR, T_UINT, T_UINT, T_INT, T_NONE}, T_INT},
[261] = {"futimesat", {T_INT, T_STR, T_ADDR, T_NONE, T_NONE, T_NONE}, T_INT},
[262] = {"newfstatat", {T_INT, T_ADDR, T_ADDR, T_INT, T_NONE, T_NONE}, T_INT},
[263] = {"unlinkat", {T_INT, T_STR, T_INT, T_NONE, T_NONE, T_NONE}, T_INT},
[264] = {"renameat", {T_INT, T_STR, T_INT, T_STR, T_NONE, T_NONE}, T_INT},
[265] = {"linkat", {T_INT, T_STR, T_INT, T_STR, T_INT, T_NONE}, T_INT},
[266] = {"symlinkat", {T_STR, T_INT, T_STR, T_NONE, T_NONE, T_NONE}, T_INT},
[267] = {"readlinkat", {T_INT, T_STR, T_STR, T_ULINT, T_NONE, T_NONE}, T_LINT},
[268] = {"fchmodat", {T_INT, T_STR, T_UINT, T_INT, T_NONE, T_NONE}, T_INT},
[269] = {"faccessat", {T_INT, T_STR, T_INT, T_INT, T_NONE, T_NONE}, T_INT},
[270] = {"pselect6", {T_INT, T_ADDR, T_ADDR, T_ADDR, T_ADDR, T_ADDR}, T_INT},
[271] = {"ppoll", {T_ADDR, T_ULINT, T_ADDR, T_ADDR, T_NONE, T_NONE}, T_INT},
[272] = {"unshare", {T_INT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[273] = {"set_robust_list", {T_ADDR, T_ULINT, T_NONE, T_NONE, T_NONE, T_NONE}, T_LINT},
[274] = {"get_robust_list", {T_INT, T_ADDR, T_ADDR, T_NONE, T_NONE, T_NONE}, T_LINT},
[275] = {"splice", {T_INT, T_ADDR, T_INT, T_ADDR, T_ULINT, T_UINT}, T_LINT},
[276] = {"tee", {T_INT, T_INT, T_ULINT, T_UINT, T_NONE, T_NONE}, T_LINT},
[277] = {"sync_file_range", {T_INT, T_LINT, T_LINT, T_UINT, T_NONE, T_NONE}, T_INT},
[278] = {"vmsplice", {T_INT, T_ADDR, T_ULINT, T_UINT, T_NONE, T_NONE}, T_LINT},
[279] = {"move_pages", {T_INT, T_ULINT, T_ADDR, T_ADDR, T_ADDR, T_INT}, T_LINT},
[280] = {"utimensat", {T_INT, T_STR, T_ADDR, T_INT, T_NONE, T_NONE}, T_INT},
[281] = {"epoll_pwait", {T_INT, T_ADDR, T_INT, T_INT, T_ADDR, T_NONE}, T_INT},
[282] = {"signalfd", {T_INT, T_ADDR, T_INT, T_NONE, T_NONE, T_NONE}, T_INT},
[283] = {"timerfd_create", {T_INT, T_INT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[284] = {"eventfd", {T_UINT, T_INT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[285] = {"fallocate", {T_INT, T_INT, T_LINT, T_LINT, T_NONE, T_NONE}, T_INT},
[286] = {"timerfd_settime", {T_INT, T_INT, T_ADDR, T_ADDR, T_NONE, T_NONE}, T_INT},
[287] = {"timerfd_gettime", {T_INT, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[288] = {"accept4", {T_INT, T_ADDR, T_ADDR, T_INT, T_NONE, T_NONE}, T_INT},
[289] = {"signalfd4", {T_INT, T_ADDR, T_INT, T_NONE, T_NONE, T_NONE}, T_INT},
[290] = {"eventfd2", {T_UINT, T_INT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[291] = {"epoll_create1", {T_INT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[292] = {"dup3", {T_INT, T_INT, T_INT, T_NONE, T_NONE, T_NONE}, T_INT},
[293] = {"pipe2", {T_ADDR, T_INT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[294] = {"inotify_init1", {T_INT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[295] = {"preadv", {T_INT, T_ADDR, T_INT, T_LINT, T_NONE, T_NONE}, T_LINT},
[296] = {"pwritev", {T_INT, T_ADDR, T_INT, T_LINT, T_NONE, T_NONE}, T_LINT},
[297] = {"rt_tgsigqueueinfo", {T_INT, T_INT, T_INT, T_ADDR, T_NONE, T_NONE}, T_INT},
[298] = {"perf_event_open", {T_ADDR, T_INT, T_INT, T_INT, T_ULINT, T_NONE}, T_INT},
[299] = {"recvmmsg", {T_INT, T_ADDR, T_UINT, T_INT, T_ADDR, T_NONE}, T_INT},
[300] = {"fanotify_init", {T_UINT, T_UINT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[301] = {"fanotify_mark", {T_INT, T_UINT, T_ULINT, T_INT, T_STR, T_NONE}, T_INT},
[302] = {"prlimit", {T_INT, T_INT, T_ADDR, T_ADDR, T_NONE, T_NONE}, T_INT},
[303] = {"name_to_handle_at", {T_INT, T_STR, T_ADDR, T_ADDR, T_INT, T_NONE}, T_INT},
[304] = {"open_by_handle_at", {T_INT, T_ADDR, T_INT, T_NONE, T_NONE, T_NONE}, T_INT},
[305] = {"clock_adjtime", {T_HEX, T_ADDR, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[306] = {"syncfs", {T_INT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[307] = {"sendmmsg", {T_INT, T_ADDR, T_UINT, T_INT, T_NONE, T_NONE}, T_INT},
[308] = {"setns", {T_INT, T_INT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[309] = {"getcpu", {T_ADDR, T_ADDR, T_ADDR, T_NONE, T_NONE, T_NONE}, T_INT},
[310] = {"process_vm_readv", {T_INT, T_ADDR, T_ULINT, T_ADDR, T_ULINT, T_ULINT}, T_LINT},
[311] = {"process_vm_writev", {T_INT, T_ADDR, T_ULINT, T_ADDR, T_ULINT, T_ULINT}, T_LINT},
[312] = {"kcmp", {T_INT, T_INT, T_INT, T_ULINT, T_ULINT, T_NONE}, T_INT},
[313] = {"finit_module", {T_INT, T_STR, T_INT, T_NONE, T_NONE, T_NONE}, T_INT},
[314] = {"sched_setattr", {T_INT, T_ADDR, T_UINT, T_NONE, T_NONE, T_NONE}, T_INT},
[315] = {"sched_getattr", {T_INT, T_ADDR, T_UINT, T_UINT, T_NONE, T_NONE}, T_INT},
[316] = {"renameat2", {T_INT, T_STR, T_INT, T_STR, T_UINT, T_NONE}, T_INT},
[317] = {"seccomp", {T_UINT, T_UINT, T_ADDR, T_NONE, T_NONE, T_NONE}, T_INT},
[318] = {"getrandom", {T_ADDR, T_ULINT, T_UINT, T_NONE, T_NONE, T_NONE}, T_LINT},
[319] = {"memfd_create", {T_STR, T_UINT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[320] = {"kexec_file_load", {T_INT, T_INT, T_ULINT, T_STR, T_ULINT, T_NONE}, T_LINT},
[321] = {"bpf", {T_INT, T_ADDR, T_UINT, T_NONE, T_NONE, T_NONE}, T_INT},
[322] = {"execveat", {T_INT, T_STR, T_ADDR, T_ADDR, T_INT, T_NONE}, T_INT},
[323] = {"userfaultfd", {T_INT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[324] = {"membarrier", {T_INT, T_INT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[325] = {"mlock2", {T_ADDR, T_ULINT, T_INT, T_NONE, T_NONE, T_NONE}, T_INT},
[326] = {"copy_file_range", {T_INT, T_ADDR, T_INT, T_ADDR, T_ULINT, T_UINT}, T_LINT},
[327] = {"preadv2", {T_INT, T_ADDR, T_INT, T_LINT, T_INT, T_NONE}, T_LINT},
[328] = {"pwritev2", {T_INT, T_ADDR, T_INT, T_LINT, T_INT, T_NONE}, T_LINT},
[329] = {"pkey_mprotect", {T_ADDR, T_ULINT, T_INT, T_INT, T_NONE, T_NONE}, T_INT},
[330] = {"pkey_alloc", {T_UINT, T_UINT, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[331] = {"pkey_free", {T_INT, T_NONE, T_NONE, T_NONE, T_NONE, T_NONE}, T_INT},
[332] = {"statx", {T_INT, T_STR, T_INT, T_UINT, T_ADDR, T_NONE}, T_INT},
[333] = {"io_pgetevents", {T_ULINT, T_LINT, T_LINT, T_ADDR, T_ADDR, T_NONE}, T_INT},
[334] = {"rseq", {T_ADDR, T_HEX, T_HEX, T_HEX, T_NONE, T_NONE}, T_INT}