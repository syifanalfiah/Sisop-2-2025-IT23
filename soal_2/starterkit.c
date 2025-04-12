#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <ctype.h>
#include <locale.h>

static pid_t daemon_pid = -1;
static int pid_logged = 0;

static pid_t find_daemon_process(void);
static void write_log(const char *action, const char *filename, int pid);
static char* base64_decode(const char *input);
static void daemon_work(void);
static void start_daemon(void);
static void stop_daemon(void);
static void move_files(const char *from, const char *to, const char *action);
static void delete_all_files(void);
static int run_program(char *program, char **args);
static int needs_download(void);
static void download_starter_kit(void);
static void create_directory(const char *path);
static void sanitize_filename(char *filename);

void sanitize_filename(char *filename) {
    if (!filename) return;
    
    for (char *p = filename; *p; ++p) {
        if (!isprint((unsigned char)*p)) {
            *p = '_';
        }
    }
}

void write_log(const char *action, const char *filename, int pid) {
    setlocale(LC_ALL, "C");
    time_t now = time(NULL);
    struct tm *timeinfo = localtime(&now);
    char timestamp[20];
    
    strftime(timestamp, sizeof(timestamp), "%d-%m-%Y][%H:%M:%S", timeinfo);

    FILE *log = fopen("activity.log", "a");
    if (!log) {
        perror("Failed to open log file");
        return;
    }

    if (strcmp(action, "Decrypt") == 0) {
        if (!pid_logged || daemon_pid != pid) {
            fprintf(log, "Decrypt: [%s] - Successfully started decryption process with PID %d.\n", 
                    timestamp, pid);
            daemon_pid = pid;
            pid_logged = 1;
        }
    }
    else if (strcmp(action, "Shutdown") == 0) {
        fprintf(log, "Shutdown: [%s] - Successfully shut off decryption process with PID %d.\n", 
                timestamp, pid);
        pid_logged = 0;
    }
    else if (strcmp(action, "Quarantine") == 0 || 
             strcmp(action, "Return") == 0 || 
             strcmp(action, "Eradicate") == 0) {
        char clean_name[256] = {0};
        if (filename) {
            strncpy(clean_name, filename, sizeof(clean_name)-1);
            sanitize_filename(clean_name);
        }
        fprintf(log, "%s: [%s] - %s - Successfully %s.\n", 
                action, timestamp, clean_name,
                strcmp(action, "Quarantine") == 0 ? "moved to quarantine directory" :
                strcmp(action, "Return") == 0 ? "returned to starter kit directory" : "deleted");
    }

    fflush(log);
    fclose(log);
}

pid_t find_daemon_process(void) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "pgrep -f 'starterkit --decrypt'");
    FILE *pgrep = popen(cmd, "r");
    if (!pgrep) return -1;

    pid_t found_pid = -1;
    if (fscanf(pgrep, "%d", &found_pid) != 1) {
        found_pid = -1;
    }
    pclose(pgrep);

    return found_pid;
}

char* base64_decode(const char *input) {
    BIO *bio, *b64;
    char *buffer = malloc(strlen(input) + 1);
    int length = 0;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf((void*)input, -1);
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    length = BIO_read(bio, buffer, strlen(input));
    buffer[length] = '\0';

    BIO_free_all(bio);
    return buffer;
}

void daemon_work(void) {
    DIR *dir;
    struct dirent *ent;
    char path[1024];

    while (1) {
        dir = opendir("starter_kit");
        if (dir) {
            while ((ent = readdir(dir)) != NULL) {
                if (ent->d_type == DT_REG) {
                    char *decoded_name = base64_decode(ent->d_name);
                    char new_path[1024];

                    snprintf(path, sizeof(path), "starter_kit/%s", ent->d_name);
                    snprintf(new_path, sizeof(new_path), "starter_kit/%s", decoded_name);

                    if (rename(path, new_path) != 0) {
                        perror("Failed to rename file");
                    }
                    free(decoded_name);
                }
            }
            closedir(dir);
        }
        sleep(5);
    }
}

void start_daemon(void) {
    pid_t existing_pid = find_daemon_process();
    if (existing_pid != -1) {
        printf("Decryption process already running with PID %d\n", existing_pid);
        write_log("Decrypt", NULL, existing_pid);
        exit(EXIT_SUCCESS);
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("Failed to fork daemon process");
        exit(EXIT_FAILURE);
    }

    if (pid > 0) {
        write_log("Decrypt", NULL, pid);
        printf("Decryption process started with PID: %d\n", pid);
        exit(EXIT_SUCCESS);
    }

    umask(0);
    setsid();
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    daemon_work(); 
}

void stop_daemon(void) {
    pid_t pid = find_daemon_process();
    if (pid == -1) {
        printf("No decryption process found\n");
        return;
    }

    if (kill(pid, SIGTERM) == 0) {
        for (int i = 0; i < 5; i++) {
            sleep(1);
            if (kill(pid, 0) == -1 && errno == ESRCH) {
                write_log("Shutdown", NULL, pid);
                printf("Successfully stopped decryption process (PID %d)\n", pid);
                return;
            }
        }
        printf("Failed to stop process %d (timeout)\n", pid);
    } else {
        if (errno == ESRCH) {
            printf("Process with PID %d not found\n", pid);
        } else {
            perror("Failed to stop process");
        }
    }
}

void create_directory(const char *path) {
    if (access(path, F_OK) == -1) {
        if (mkdir(path, 0755) == -1) {
            perror("Failed to create directory");
            exit(EXIT_FAILURE);
        }
    }
}

int needs_download(void) {
    DIR *dir = opendir("starter_kit");
    if (dir == NULL) return 1;

    struct dirent *ent;
    int count = 0;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0) {
            count++;
            break;
        }
    }
    closedir(dir);

    return count == 0;
}

int run_program(char *program, char **args) {
    pid_t pid = fork();

    if (pid < 0) {
        perror("Failed to create process");
        return -1;
    } else if (pid == 0) {
        execvp(program, args);
        perror("Failed to execute program");
        exit(EXIT_FAILURE);
    } else {
        int status;
        waitpid(pid, &status, 0);
        return WEXITSTATUS(status);
    }
}

void download_starter_kit(void) {
    if (!needs_download()) {
        printf("Starter kit already exists, skipping download\n");
        return;
    }

    create_directory("starter_kit");
    create_directory("quarantine");

    printf("Downloading starter kit...\n");
    char *wget_args[] = {
        "wget", "--no-check-certificate",
        "https://drive.google.com/uc?export=download&id=1_5GxIGfQr3mNKuavJbte_AoRkEQLXSKS",
        "-O", "starter_kit.zip", NULL
    };

    if (run_program("wget", wget_args) == 0) {
        char *unzip_args[] = {
            "unzip", "-o", "starter_kit.zip", "-d", "starter_kit", NULL
        };
        if (run_program("unzip", unzip_args) == 0) {
            printf("Starter kit downloaded and extracted successfully\n");
            remove("starter_kit.zip");
        } else {
            printf("Failed to extract starter kit\n");
        }
    } else {
        printf("Failed to download starter kit\n");
    }
}

void move_files(const char *from, const char *to, const char *action) {
    DIR *dir;
    struct dirent *ent;
    char src_path[1024];
    char dst_path[1024];

    dir = opendir(from);
    if (dir == NULL) {
        perror("Failed to open directory");
        return;
    }

    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_type == DT_REG) {
            snprintf(src_path, sizeof(src_path), "%s/%s", from, ent->d_name);
            snprintf(dst_path, sizeof(dst_path), "%s/%s", to, ent->d_name);

            if (rename(src_path, dst_path) == 0) {
                write_log(action, ent->d_name, 0);
                printf("%s successfully %s\n", ent->d_name, 
                       strcmp(action, "Quarantine") == 0 ? "quarantined" : "returned");
            } else {
                perror("Failed to move file");
            }
        }
    }

    closedir(dir);
}

void delete_all_files(void) {
    DIR *dir;
    struct dirent *ent;
    char path[1024];

    dir = opendir("quarantine");
    if (dir == NULL) {
        perror("Failed to open quarantine directory");
        return;
    }

    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_type == DT_REG) {
            snprintf(path, sizeof(path), "quarantine/%s", ent->d_name);

            if (remove(path) == 0) {
                write_log("Eradicate", ent->d_name, 0);
                printf("%s successfully deleted\n", ent->d_name);
            } else {
                perror("Failed to delete file");
            }
        }
    }

    closedir(dir);
}

int main(int argc, char *argv[]) {
    setlocale(LC_ALL, "C");

    if (argc != 2) {
        printf("Usage: %s [--decrypt|--quarantine|--return|--eradicate|--shutdown]\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "--return") != 0) {
        download_starter_kit();
    } else {
        create_directory("quarantine");
    }

    if (strcmp(argv[1], "--decrypt") == 0) {
        start_daemon();
    } 
    else if (strcmp(argv[1], "--quarantine") == 0) {
        move_files("starter_kit", "quarantine", "Quarantine");
    }
    else if (strcmp(argv[1], "--return") == 0) {
        move_files("quarantine", "starter_kit", "Return");
    }
    else if (strcmp(argv[1], "--eradicate") == 0) {
        delete_all_files();
    }
    else if (strcmp(argv[1], "--shutdown") == 0) {
        stop_daemon();
    }
    else {
        printf("Unknown argument: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
