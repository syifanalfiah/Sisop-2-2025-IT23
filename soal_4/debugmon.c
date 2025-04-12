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

#define MAX_PROCESSES 1024
#define LOG_FILE "debugmon.log"
#define PID_FILE "/tmp/debugmon_daemon.pid"

typedef struct {
    pid_t pid;
    char command[256];
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
    char command[256];
    sprintf(command, "ps -u %s -o pid,comm,%%cpu,%%mem --no-headers 2>/dev/null", user);
    
    FILE *ps_output = popen(command, "r");
    if (!ps_output) {
        printf("Error: Gagal menjalankan perintah ps\n");
        return 0;
    }

    int count = 0;
    while (fscanf(ps_output, "%d %s %f %f", 
                 &processes[count].pid, 
                 processes[count].command,
                 &processes[count].cpu_usage,
                 &processes[count].mem_usage) == 4 && count < MAX_PROCESSES-1) {
        count++;
    }

    pclose(ps_output);
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
        // Simpan PID ke file
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
            sprintf(log_entry, "daemon_%s_%d", processes[i].command, processes[i].pid);
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
                sprintf(log_entry, "fail_%s_%d", processes[i].command, processes[i].pid);
                log_action(log_entry, "FAILED");
            } else {
                printf("Gagal (errno: %d)\n", errno);
            }
        }
    }

    printf("\nMemblokir user %s...\n", user);
    char command[256];
    sprintf(command, "sudo usermod -s /bin/false %s", user);
    int result = system(command);
    if (result == 0) {
        printf("User %s berhasil diblokir\n", user);
        log_action("user_block", "FAILED");
    } else {
        printf("Gagal memblokir user (perlu sudo?)\n");
    }
}

void revert_changes(const char *user) {
    printf("\n=== Mengembalikan Akses ===\n");
    printf("Memulihkan akses untuk user %s...\n", user);
    
    char command[256];
    sprintf(command, "sudo usermod -s /bin/bash %s", user);
    int result = system(command);
    
    if (result == 0) {
        printf("Akses user %s berhasil dipulihkan\n", user);
    } else {
        printf("Gagal memulihkan akses (perlu sudo?)\n");
    }
    log_action("revert", "RUNNING");
}

int main(int argc, char *argv[]) {
    printf("\n=== Debugmon Monitoring Tool ===\n");
    printf("Dijalankan sebagai user: %s\n", getenv("USER"));
    
    if (argc < 3) {
        printf("\nUsage: %s <command> <user>\n", argv[0]);
        printf("Commands:\n");
        printf("  list    - List processes for user\n");
        printf("  daemon  - Start monitoring daemon\n");
        printf("  stop    - Stop monitoring daemon\n");
        printf("  fail    - Kill all processes and block user (need sudo)\n");
        printf("  revert  - Restore user access (need sudo)\n");
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
