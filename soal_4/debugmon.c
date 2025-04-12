#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>
#include <sys/wait.h>
#include <ctype.h> 

#define MAX_PROCESSES 1024
#define LOG_FILE "debugmon.log"
#define PID_FILE "/tmp/debugmon_daemon.pid"

typedef struct {
    pid_t pid;
    char command[512];
    float cpu_usage;
    float mem_usage;
} ProcessInfo;

void log_action(const char *process, const char *status) {
    time_t now;
    time(&now);
    struct tm *tm = localtime(&now);
    
    FILE *log = fopen(LOG_FILE, "a");
    if (log) {
        fprintf(log, "[%02d:%02d:%04d]-[%02d:%02d:%02d]_%s_STATUS(%s)\n",
                tm->tm_mday, tm->tm_mon+1, tm->tm_year+1900,
                tm->tm_hour, tm->tm_min, tm->tm_sec,
                process, status);
        fclose(log);
    }
}

int get_user_processes(const char *user, ProcessInfo *processes) {
    struct passwd *pwd = getpwnam(user);
    if (!pwd) {
        printf("Error: User %s not found\n", user);
        return 0;
    }
    uid_t uid = pwd->pw_uid;

    DIR *dir;
    struct dirent *entry;
    char path[512], line[1024];
    FILE *file;
    int count = 0;

    if (!(dir = opendir("/proc"))) {
        perror("opendir /proc");
        return 0;
    }

    while ((entry = readdir(dir)) != NULL && count < MAX_PROCESSES-1) {
        if (entry->d_type != DT_DIR || !isdigit(entry->d_name[0]))
            continue;
        snprintf(path, sizeof(path), "/proc/%s/status", entry->d_name);
        if ((file = fopen(path, "r"))) {
            pid_t pid = atoi(entry->d_name);
            uid_t proc_uid = 0;
            char name[512] = {0};
            while (fgets(line, sizeof(line), file)) {
                if (strncmp(line, "Name:", 5) == 0) {
                    sscanf(line + 5, "%255s", name);
                } else if (strncmp(line, "Uid:", 4) == 0) {
                    // Uid line contains real, effective, saved, and filesystem UIDs
                    sscanf(line + 4, "%*d%d", &proc_uid);
                }
            }
            fclose(file);

            if (proc_uid == uid) {
                snprintf(path, sizeof(path), "/proc/%s/stat", entry->d_name);
                if ((file = fopen(path, "r"))) {
                    unsigned long utime, stime;
                    long rss;
                    fscanf(file, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu %*d %*d %*d %*d %*d %*d %*u %lu",
                           &utime, &stime, &rss);
                    fclose(file);

                    float cpu_usage = (utime + stime) / 100.0;

                    long page_size = sysconf(_SC_PAGESIZE);
                    float mem_usage = (rss * page_size) / (1024.0 * 1024.0); // in MB

                    processes[count].pid = pid;
                    strncpy(processes[count].command, name, sizeof(processes[count].command)-1);
                    processes[count].cpu_usage = cpu_usage;
                    processes[count].mem_usage = mem_usage;
                    count++;
                }
            }
        }
    }
    closedir(dir);
    return count;
}

void list_processes(const char *user) {
    printf("\n=== Memproses Daftar Proses ===\n");
    ProcessInfo processes[MAX_PROCESSES];
    int count = get_user_processes(user, processes);

    if (count == 0) {
        printf("Tidak ada proses yang berjalan untuk user %s\n", user);
    } else {
        printf("Daftar proses %s (%d ditemukan):\n", user, count);
        printf("PID\tCOMMAND\t\tCPU%%\tMEM%%\n");
        for (int i = 0; i < count; i++) {
            printf("%d\t%s\t%.1f\t%.1f\n", 
                   processes[i].pid, 
                   processes[i].command,
                   processes[i].cpu_usage,
                   processes[i].mem_usage);
        }
    }
    log_action("list", "RUNNING");
}

void start_daemon(const char *user) {
    printf("\n=== Memulai Daemon ===\n");
    pid_t pid = fork();
    if (pid < 0) {
        printf("Error: Gagal membuat proses daemon!\n");
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        FILE *pid_file = fopen(PID_FILE, "w");
        if (pid_file) {
            fprintf(pid_file, "%d", pid);
            fclose(pid_file);
            printf("PID daemon disimpan di %s\n", PID_FILE);
        } else {
            printf("Peringatan: Gagal menyimpan PID daemon\n");
        }
        printf("Daemon berjalan dengan PID: %d\n", pid);
        log_action("daemon_start", "RUNNING");
        exit(EXIT_SUCCESS);
    }

    umask(0);
    setsid();
    chdir("/");

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    while (1) {
        ProcessInfo processes[MAX_PROCESSES];
        int count = get_user_processes(user, processes);
        for (int i = 0; i < count; i++) {
            char log_entry[512];
            snprintf(log_entry, sizeof(log_entry), "daemon_%s_%d", processes[i].command, processes[i].pid);
            log_action(log_entry, "RUNNING");
        }
        sleep(5);
    }
}

void stop_daemon(const char *user) {
    printf("\n=== Menghentikan Daemon ===\n");
    
    FILE *pid_file = fopen(PID_FILE, "r");
    if (!pid_file) {
        printf("Error: File PID tidak ditemukan di %s\n", PID_FILE);
        printf("Coba cek PID manual dengan: ps aux | grep debugmon\n");
        return;
    }
    
    pid_t pid;
    if (fscanf(pid_file, "%d", &pid) != 1) {
        printf("Error: Gagal membaca PID dari file\n");
        fclose(pid_file);
        return;
    }
    fclose(pid_file);
    
    printf("Menghentikan daemon dengan PID %d...\n", pid);
    
    if (kill(pid, SIGTERM) == 0) {
        printf("Daemon berhasil dihentikan\n");
        remove(PID_FILE);
    } else {
        printf("Error: Gagal menghentikan daemon (errno: %d)\n", errno);
        printf("Coba hentikan paksa dengan: kill -9 %d\n", pid);
    }
    log_action("stop_daemon", "RUNNING");
}

void fail_processes(const char *user) {
    printf("\n=== Menggagalkan Proses ===\n");
    ProcessInfo processes[MAX_PROCESSES];
    int count = get_user_processes(user, processes);

    if (count == 0) {
        printf("Tidak ada proses yang berjalan untuk user %s\n", user);
    } else {
        printf("Menemukan %d proses untuk digagalkan:\n", count);
        for (int i = 0; i < count; i++) {
            printf("Menghentikan proses %d (%s)... ", processes[i].pid, processes[i].command);
            if (kill(processes[i].pid, SIGKILL) == 0) {
                printf("Berhasil\n");
                char log_entry[512];
                snprintf(log_entry, sizeof(log_entry), "fail_%s_%d", processes[i].command, processes[i].pid);
                log_action(log_entry, "FAILED");
            } else {
                printf("Gagal (errno: %d)\n", errno);
            }
        }
    }

    printf("\nMemblokir user %s...\n", user);

    FILE *passwd = fopen("/etc/passwd", "r");
    if (!passwd) {
        perror("fopen /etc/passwd");
        return;
    }
    
    FILE *tmp = fopen("/etc/passwd.tmp", "w");
    if (!tmp) {
        perror("fopen /etc/passwd.tmp");
        fclose(passwd);
        return;
    }
    
    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), passwd)) {
        char *colon = strchr(line, ':');
        if (colon) {
            *colon = '\0';
            if (strcmp(line, user) == 0) {
                found = 1;
                char *last_colon = strrchr(line, ':');
                if (last_colon) {
                    strcpy(last_colon + 1, "/bin/false\n");
                }
            }
            *colon = ':';
        }
        fputs(line, tmp);
    }
    
    fclose(passwd);
    fclose(tmp);
    
    if (found) {
        if (rename("/etc/passwd.tmp", "/etc/passwd") == 0) {
            printf("User %s berhasil diblokir\n", user);
            log_action("user_block", "FAILED");
        } else {
            perror("rename");
            printf("Gagal memblokir user\n");
            remove("/etc/passwd.tmp");
        }
    } else {
        printf("User %s tidak ditemukan\n", user);
        remove("/etc/passwd.tmp");
    }
}

void revert_changes(const char *user) {
    printf("\n=== Mengembalikan Akses ===\n");
    printf("Memulihkan akses untuk user %s...\n", user);
 
    FILE *passwd = fopen("/etc/passwd", "r");
    if (!passwd) {
        perror("fopen /etc/passwd");
        return;
    }
    
    FILE *tmp = fopen("/etc/passwd.tmp", "w");
    if (!tmp) {
        perror("fopen /etc/passwd.tmp");
        fclose(passwd);
        return;
    }
    
    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), passwd)) {
        char *colon = strchr(line, ':');
        if (colon) {
            *colon = '\0';
            if (strcmp(line, user) == 0) {
                found = 1;
                // Find the last colon (shell field)
                char *last_colon = strrchr(line, ':');
                if (last_colon) {
                    strcpy(last_colon + 1, "/bin/bash\n");
                }
            }
            *colon = ':';
        }
        fputs(line, tmp);
    }
    
    fclose(passwd);
    fclose(tmp);
    
    if (found) {
        if (rename("/etc/passwd.tmp", "/etc/passwd") == 0) {
            printf("Akses user %s berhasil dipulihkan\n", user);
            log_action("revert", "RUNNING");
        } else {
            perror("rename");
            printf("Gagal memulihkan akses\n");
            remove("/etc/passwd.tmp");
        }
    } else {
        printf("User %s tidak ditemukan\n", user);
        remove("/etc/passwd.tmp");
    }
}

int main(int argc, char *argv[]) {
    printf("\n=== Debugmon Monitoring Tool ===\n");

    uid_t uid = getuid();
    struct passwd *pw = getpwuid(uid);
    if (pw) {
        printf("Dijalankan sebagai user: %s\n", pw->pw_name);
    }
    
    if (argc < 3) {
        printf("\nUsage: %s <command> <user>\n", argv[0]);
        printf("Commands:\n");
        printf("  list    - List processes for user\n");
        printf("  daemon  - Start monitoring daemon\n");
        printf("  stop    - Stop monitoring daemon\n");
        printf("  fail    - Kill all processes and block user (need root)\n");
        printf("  revert  - Restore user access (need root)\n");
        return 1;
    }

    printf("\nCommand: %s %s\n", argv[1], argv[2]);

    if (strcmp(argv[1], "list") == 0) {
        list_processes(argv[2]);
    } else if (strcmp(argv[1], "daemon") == 0) {
        start_daemon(argv[2]);
    } else if (strcmp(argv[1], "stop") == 0) {
        stop_daemon(argv[2]);
    } else if (strcmp(argv[1], "fail") == 0) {
        fail_processes(argv[2]);
    } else if (strcmp(argv[1], "revert") == 0) {
        revert_changes(argv[2]);
    } else {
        printf("Error: Perintah tidak dikenali!\n");
    }

    printf("\nSelesai.\n");
    return 0;
}
