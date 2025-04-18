# Laporan Praktikum Modul 2

## Nama Anggota

| Nama                        | NRP        |
| --------------------------- | ---------- |
| Syifa Nurul Alfiah          | 5027241019 |
| Alnico Virendra Kitaro Diaz | 5027241081 |
| Hafiz Ramadhan              | 5027241096 |

## Soal No 1

## Soal No 2

### Penjelasan
Program ini merupakan sistem daemon yang berjalan di background dan menangani proses dekripsi nama file dari folder starter_kit. Selain itu, tersedia fitur untuk karantina file, mengembalikannya, menghapusnya secara permanen, serta mencatat semua aktivitas ke dalam file log (activity.log).

Program ini menggunakan beberapa library standard C dan OpenSSL:
- dirent.h, unistd.h, fcntl.h untuk manipulasi file dan direktori
- sys/types.h, sys/stat.h, signal.h, wait.h untuk daemon dan proses
- openssl/bio.h, openssl/evp.h untuk proses dekripsi Base64
- ctype.h, locale.h untuk validasi karakter
- time.h untuk timestamp log

### Fungsi Kode

1. void tulis_log(const char *aksi, const char *nama_file, int pid)
```c
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
        char clean_name[512] = {0};
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
        char clean_name[512] = {0};
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
        char clean_name[512] = {0};
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
```
Mencatat aktivitas ke file activity.log dengan timestamp, nama file, dan PID (jika relevan). Aktivitas yang dicatat misalnya: Decrypt, Quarantine, Return, Eradicate, Shutdown.
- aksi: jenis aktivitas/log yang akan ditulis (string seperti "Decrypt", "Quarantine", dll)
- nama_file: nama file yang terlibat (bisa NULL jika tak ada)
- pid: ID proses yang relevan untuk log (biasanya untuk log decrypt/shutdown)

2. char* dekripsi_base64(const char *input)
```c
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
```
Melakukan decoding string dari Base64 menjadi bentuk aslinya (digunakan untuk nama file yang disamarkan).
- Argumen: input: string dalam format Base64
- Return: Hasil decode sebagai string (char pointer), harus di-free() setelah dipakai.

3. void proses_daemon()
```c
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
```
4. pid_t cari_pid_daemon()
```c
pid_t cari_pid_daemon() {
    FILE *pid_file = fopen("decrypt.pid", "r");
    if (pid_file) {
        pid_t pid;
        if (fscanf(pid_file, "%d", &pid) == 1) {
            fclose(pid_file);
            char cmdline[512] = {0};
            char path[512];
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
            char path[512];
            char cmdline[512] = {0};
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
```
Mengecek apakah proses daemon (starterkit dengan argumen --decrypt) sudah berjalan. Cek melalui file decrypt.pid atau dari direktori /proc.
- Return: PID dari proses daemon kalau ketemu, -1 kalau tidak ada.

5. void mulai_daemon()
```c
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
```
Memulai proses daemon baru jika belum ada yang berjalan. Menulis PID ke decrypt.pid dan mencatat log "Decrypt". Proses anak (child) akan menjalankan proses_daemon().

6. void hentikan_daemon()
```c
void hentikan_daemon() {
    pid_t current_pid = cari_pid_daemon();
    
    if (current_pid == -1) {
        printf("Tidak ada proses decrypt yang berjalan\n");
        remove("decrypt.pid");
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
```

7. void pindahkan_file(const char *dari, const char *ke, const char *aksi)
```c
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
```
Memindahkan semua file dari direktori dari ke ke, dan mencatat log untuk setiap file sesuai aksi ("Quarantine" atau "Return").
- Argumen:
1. dari: nama direktori sumber
2. ke: nama direktori tujuan
3. aksi: aksi untuk log (misalnya "Quarantine" atau "Return")

8. void hapus_semua_file()
```c
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
```
Menghapus semua file reguler dari direktori quarantine. Setiap penghapusan dicatat di log sebagai "Eradicate".

9. int jalankan_program(char *program, char **args)
```c
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
```
Menjalankan program eksternal (seperti wget, unzip, dll) lewat fork + execvp.
- char *program: nama program yang mau dijalankan (misal "wget")
- char **args: array of arguments-nya (misal {"wget", "-O", "file.zip", NULL})
Isi:
pid_t pid = fork();  // buat proses anak
- Kalau fork() gagal → cetak error dan return -1
- Kalau pid == 0 → berarti ini proses anak → jalankan execvp(program, args)
- Kalau gagal → cetak pesan dan exit
- Kalau pid > 0 → proses induk → tunggu anak selesai dengan waitpid(), lalu return exit status-nya

10. int perlu_download()
```c
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
```
Cek apakah folder starter_kit kosong atau belum ada → buat tahu apakah perlu download atau nggak.
Isi:
- DIR *dir = opendir("starter_kit"); → buka direktori
- Kalau gagal (folder gak ada) → return 1 (perlu download)
- Kalau folder ada → baca isinya:
- Kalau isinya selain . dan .. ada → return 0 (nggak perlu download)
- Kalau kosong → return 1 (perlu download)

11. void unduh_starter_kit()
```c
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
```
Download file zip dari Google Drive dan unzip ke folder starter_kit, kalau belum ada.
Jalankan wget → kalau sukses: Jalankan unzip ke folder starter_kit 
- Kalau sukses → hapus starter_kit.zip
- Kalau gagal → tampilkan error unzip
- Kalau wget gagal → tampilkan error download

### Penjelasan
Fungsi:
Menangani argumen perintah yang diketikkan user dari terminal seperti:
```c
./namafile --decrypt
```

1. Cek jumlah argumen:
```c
if (argc != 2) {
    printf("Penggunaan: %s [--decrypt|--quarantine|--return|--eradicate|--shutdown]\n", argv[0]);
    return EXIT_FAILURE;
}
```
- argc: jumlah argumen, termasuk nama program
- argv[0]: nama program
- argv[1]: perintah user (misal: --decrypt)
- Kalau gak ada argumen → tampilkan cara pakai

2. Cek apakah program decrypt sedang jalan:
```c
if (access("decrypt.pid", F_OK) == 0) {
    FILE *pid_file = fopen("decrypt.pid", "r");
    ...
    if (kill(old_pid, 0) == -1 && errno == ESRCH) {
        remove("decrypt.pid");
    }
}
```
- Cek apakah file decrypt.pid ada (penanda proses decrypt)
- Kalau ada, baca isinya (isinya PID proses decrypt lama)
- Pakai kill(pid, 0) untuk cek apakah proses itu masih hidup
- Kalau udah mati → hapus file .pid-nya (biar bersih)

3. Jalankan unduh_starter_kit() kecuali argumen --return:
```c
if (strcmp(argv[1], "--return") != 0) {
    unduh_starter_kit();
} else {
    if (access("quarantine", F_OK) == -1) {
        mkdir("quarantine", 0755);
    }
}
```
- Kalau bukan --return, maka jalankan fungsi download starter kit
- Kalau --return, pastikan folder quarantine ada

4. Pilih aksi sesuai argumen:
```c
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
```
Argumen	Fungsi yang dijalankan	Keterangan Singkat
1. --decrypt	mulai_daemon()	Menjalankan proses latar (decrypt)
2. --quarantine	pindahkan_file(starter_kit → quarantine)	Memindahkan semua file ke folder quarantine
3. --return	pindahkan_file(quarantine → starter_kit)	Balikin file dari quarantine
4. --eradicate	hapus_semua_file()	Menghapus semua file (eradikasi)
5. --shutdown	hentikan_daemon()	Mematikan proses daemon decrypt
6. lainnya	Error: argumen tidak dikenal	Tampilkan pesan error

5. Return sukses:
```c
return EXIT_SUCCESS;
```

Cara Jalannya:
```c
gcc program.c -o program
```
![image](https://github.com/user-attachments/assets/c13ed983-e870-4b54-b615-7aca0f335f06)


Jalankan pakai:
```c
./program --decrypt
```
![image](https://github.com/user-attachments/assets/17590ead-203d-4878-8021-0801f1dac98b)

```c
./program --quarantine
```
![image](https://github.com/user-attachments/assets/3b2a1a87-a22d-497d-ae5a-8febb995c491)

```c
./program --return
```
![image](https://github.com/user-attachments/assets/872f97c0-ad27-4abf-8211-ec71b75396c7)

```c
./program --eradicate
```
![image](https://github.com/user-attachments/assets/40a41d82-bf2a-4e30-b7a8-8d9adee00a84)


```c
./program --shutdown
```
![image](https://github.com/user-attachments/assets/3d1d85db-1994-40f4-85f7-faed5e6ea3f1)


### Revisi

Mengubah semua isi array yang awalnya 256 menjadi 512
- Contoh:
```c
char clean_name[256] = {0};
```
jadi
```c
 char clean_name[512] = {0};
```
![image](https://github.com/user-attachments/assets/a91db3d9-65f9-4537-9b01-3edfc2256177)

## Soal No 3

## Soal No 4
