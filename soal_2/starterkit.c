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

pid_t pid_daemon = -1;

void tulis_log(const char *aksi, const char *nama_file, int pid) {
    setlocale(LC_TIME, "en_US.UTF-8");
    time_t sekarang = time(NULL);
    struct tm *waktu = localtime(&sekarang);
    char timestamp[30];
    
    strftime(timestamp, sizeof(timestamp), "%d-%m-%Y][%H:%M:%S", waktu);

    FILE *log_file = fopen("activity.log", "a");
    if (log_file == NULL) {
        perror("Gagal membuka file log");
        return;
    }

    if (strcmp(aksi, "Decrypt") == 0) {
        fprintf(log_file, "Decrypt: [%s] - Successfully started decryption process with PID %d.\n", 
                timestamp, pid);
    } 
    else if (strcmp(aksi, "Quarantine") == 0) {
        char clean_name[256] = {0};
        if (nama_file) {
            strncpy(clean_name, nama_file, sizeof(clean_name)-1);
            for (char *p = clean_name; *p; ++p) {
                if (!isprint((unsigned char)*p)) *p = '\0';
            }
        }
        fprintf(log_file, "Quarantine: [%s] - %s - Successfully moved to quarantine directory.\n", 
                timestamp, clean_name);
    }
    else if (strcmp(aksi, "Return") == 0) {
        char clean_name[256] = {0};
        if (nama_file) {
            strncpy(clean_name, nama_file, sizeof(clean_name)-1);
            for (char *p = clean_name; *p; ++p) {
                if (!isprint((unsigned char)*p)) *p = '\0';
            }
        }
        fprintf(log_file, "Return: [%s] - %s - Successfully returned to starter kit directory.\n", 
                timestamp, clean_name);
    }
    else if (strcmp(aksi, "Eradicate") == 0) {
        char clean_name[256] = {0};
        if (nama_file) {
            strncpy(clean_name, nama_file, sizeof(clean_name)-1);
            for (char *p = clean_name; *p; ++p) {
                if (!isprint((unsigned char)*p)) *p = '\0';
            }
        }
        fprintf(log_file, "Eradicate: [%s] - %s - Successfully deleted.\n", 
                timestamp, clean_name);
    }
    else if (strcmp(aksi, "Shutdown") == 0) {
        fprintf(log_file, "Shutdown: [%s] - Successfully shut off decryption process with PID %d.\n", 
                timestamp, pid);
    }

    fflush(log_file);
    fclose(log_file);
}

char* dekripsi_base64(const char *input) {
    BIO *bio, *b64;
    char *buffer = malloc(strlen(input) + 1);
    int panjang = 0;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf((void*)input, -1);
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    panjang = BIO_read(bio, buffer, strlen(input));
    buffer[panjang] = '\0';

    BIO_free_all(bio);
    return buffer;
}

void proses_daemon() {
    DIR *dir;
    struct dirent *ent;
    char path[1024];

    while (1) {
        dir = opendir("starter_kit");
        if (dir != NULL) {
            while ((ent = readdir(dir)) != NULL) {
                if (ent->d_type == DT_REG) {
                    char *nama_asli = dekripsi_base64(ent->d_name);
                    char nama_baru[1024];

                    snprintf(path, sizeof(path), "starter_kit/%s", ent->d_name);
                    snprintf(nama_baru, sizeof(nama_baru), "starter_kit/%s", nama_asli);

                    rename(path, nama_baru);
                    free(nama_asli);
                }
            }
            closedir(dir);
        }
        sleep(5);
    }
}

pid_t cari_pid_daemon() {
    FILE *pid_file = fopen("decrypt.pid", "r");
    if (pid_file) {
        pid_t pid;
        if (fscanf(pid_file, "%d", &pid) == 1) {
            fclose(pid_file);
            char cmdline[256] = {0};
            char path[256];
            snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
            FILE *cmd = fopen(path, "r");
            if (cmd) {
                fread(cmdline, 1, sizeof(cmdline), cmd);
                fclose(cmd);
                if (strstr(cmdline, "starterkit")) {
                    return pid;
                }
            }
        }
        fclose(pid_file);
    }

    DIR *dir = opendir("/proc");
    if (!dir) return -1;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_type == DT_DIR && isdigit(ent->d_name[0])) {
            char path[256];
            char cmdline[256] = {0};
            snprintf(path, sizeof(path), "/proc/%s/cmdline", ent->d_name);
            FILE *cmd = fopen(path, "r");
            if (cmd) {
                fread(cmdline, 1, sizeof(cmdline), cmd);
                fclose(cmd);
                if (strstr(cmdline, "starterkit") && strstr(cmdline, "--decrypt")) {
                    closedir(dir);
                    return atoi(ent->d_name);
                }
            }
        }
    }
    closedir(dir);
    return -1;
}

void mulai_daemon() {
    if (access("decrypt.pid", F_OK) == 0) {
        FILE *pid_file = fopen("decrypt.pid", "r");
        if (pid_file) {
            pid_t old_pid;
            if (fscanf(pid_file, "%d", &old_pid) == 1) {
                if (kill(old_pid, 0) == -1 && errno == ESRCH) {
                    remove("decrypt.pid");
                }
            }
            fclose(pid_file);
        }
    }

    pid_t existing_pid = cari_pid_daemon();
    if (existing_pid != -1) {
        printf("Proses decrypt sudah berjalan dengan PID %d\n", existing_pid);
        exit(EXIT_SUCCESS);
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("Gagal membuat daemon");
        exit(EXIT_FAILURE);
    }

    if (pid > 0) { 
        sleep(1);
        FILE *pid_file = fopen("decrypt.pid", "r");
        if (pid_file) {
            fscanf(pid_file, "%d", &pid);
            fclose(pid_file);
        }
        
        tulis_log("Decrypt", NULL, pid);
        printf("Proses decrypt berjalan dengan PID: %d\n", pid);
        exit(EXIT_SUCCESS);
    }

    umask(0);
    setsid();
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    FILE *pid_file = fopen("decrypt.pid", "w");
    if (pid_file) {
        fprintf(pid_file, "%d", getpid());
        fclose(pid_file);
    }

    sync();

    proses_daemon();
}

void hentikan_daemon() {
    pid_t current_pid = cari_pid_daemon();
    
    if (current_pid == -1) {
        printf("Tidak ada proses decrypt yang berjalan\n");
        remove("decrypt.pid"); // Clean up if file exists
        return;
    }

    printf("Menghentikan proses decrypt dengan PID %d...\n", current_pid);
    if (kill(current_pid, SIGTERM) == 0) {
        int i;
        for (i = 0; i < 5; i++) {
            sleep(1);
            if (kill(current_pid, 0) == -1 && errno == ESRCH) {
                tulis_log("Shutdown", NULL, current_pid);
                printf("Proses decrypt dengan PID %d telah dihentikan\n", current_pid);
                remove("decrypt.pid");
                return;
            }
        }
        kill(current_pid, SIGKILL);
        sleep(1);
        if (kill(current_pid, 0) == -1 && errno == ESRCH) {
            tulis_log("Shutdown", NULL, current_pid);
            printf("Proses decrypt dengan PID %d telah dihentikan (paksa)\n", current_pid);
            remove("decrypt.pid");
        } else {
            printf("Gagal menghentikan proses %d\n", current_pid);
        }
    } else {
        perror("Gagal menghentikan proses");
    }
}

void pindahkan_file(const char *dari, const char *ke, const char *aksi) {
    DIR *dir;
    struct dirent *ent;
    char path_sumber[1024];
    char path_tujuan[1024];

    dir = opendir(dari);
    if (dir == NULL) {
        perror("Gagal membuka direktori");
        return;
    }

    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_type == DT_REG) {
            snprintf(path_sumber, sizeof(path_sumber), "%s/%s", dari, ent->d_name);
            snprintf(path_tujuan, sizeof(path_tujuan), "%s/%s", ke, ent->d_name);

            if (rename(path_sumber, path_tujuan) == 0) {
                tulis_log(aksi, ent->d_name, 0);
                printf("%s berhasil dipindahkan\n", ent->d_name);
            } else {
                perror("Gagal memindahkan file");
            }
        }
    }

    closedir(dir);
}

void hapus_semua_file() {
    DIR *dir;
    struct dirent *ent;
    char path[1024];

    dir = opendir("quarantine");
    if (dir == NULL) {
        perror("Gagal membuka direktori karantina");
        return;
    }

    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_type == DT_REG) {
            snprintf(path, sizeof(path), "quarantine/%s", ent->d_name);

            if (remove(path) == 0) {
                tulis_log("Eradicate", ent->d_name, 0);
                printf("%s berhasil dihapus\n", ent->d_name);
            } else {
                perror("Gagal menghapus file");
            }
        }
    }

    closedir(dir);
}

int jalankan_program(char *program, char **args) {
    pid_t pid = fork();

    if (pid < 0) {
        perror("Gagal membuat proses");
        return -1;
    } else if (pid == 0) {
        execvp(program, args);
        perror("Gagal menjalankan program");
        exit(EXIT_FAILURE);
    } else {
        int status;
        waitpid(pid, &status, 0);
        return WEXITSTATUS(status);
    }
}

int perlu_download() {
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

void unduh_starter_kit() {
    if (!perlu_download()) {
        printf("Starter kit sudah ada, skip download\n");
        return;
    }

    if (access("starter_kit", F_OK) == -1) {
        mkdir("starter_kit", 0755);
    }

    if (access("quarantine", F_OK) == -1) {
        mkdir("quarantine", 0755);
    }

    printf("Mengunduh starter kit...\n");
    char *wget_args[] = {"wget", "--no-check-certificate",
                         "https://drive.google.com/uc?export=download&id=1_5GxIGfQr3mNKuavJbte_AoRkEQLXSKS",
                         "-O", "starter_kit.zip", NULL};

    if (jalankan_program("wget", wget_args) == 0) {
        char *unzip_args[] = {"unzip", "-o", "starter_kit.zip", "-d", "starter_kit", NULL};
        if (jalankan_program("unzip", unzip_args) == 0) {
            printf("Starter kit berhasil diunduh dan diekstrak\n");
            remove("starter_kit.zip");
        } else {
            printf("Gagal mengekstrak starter kit\n");
        }
    } else {
        printf("Gagal mengunduh starter kit\n");
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Penggunaan: %s [--decrypt|--quarantine|--return|--eradicate|--shutdown]\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (access("decrypt.pid", F_OK) == 0) {
        FILE *pid_file = fopen("decrypt.pid", "r");
        if (pid_file) {
            pid_t old_pid;
            if (fscanf(pid_file, "%d", &old_pid) == 1) {
                if (kill(old_pid, 0) == -1 && errno == ESRCH) {
                    remove("decrypt.pid");
                }
            }
            fclose(pid_file);
        }
    }

    if (strcmp(argv[1], "--return") != 0) {
        unduh_starter_kit();
    } else {
        if (access("quarantine", F_OK) == -1) {
            mkdir("quarantine", 0755);
        }
    }

    if (strcmp(argv[1], "--decrypt") == 0) {
        mulai_daemon();
    } else if (strcmp(argv[1], "--quarantine") == 0) {
        pindahkan_file("starter_kit", "quarantine", "Quarantine");
    } else if (strcmp(argv[1], "--return") == 0) {
        pindahkan_file("quarantine", "starter_kit", "Return");
    } else if (strcmp(argv[1], "--eradicate") == 0) {
        hapus_semua_file();
    } else if (strcmp(argv[1], "--shutdown") == 0) {
        hentikan_daemon();
    } else {
        printf("Argumen tidak dikenal: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
