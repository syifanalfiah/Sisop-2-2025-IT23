# Laporan Praktikum Modul 2

## Nama Anggota

| Nama                        | NRP        |
| --------------------------- | ---------- |
| Syifa Nurul Alfiah          | 5027241019 |
| Alnico Virendra Kitaro Diaz | 5027241081 |
| Hafiz Ramadhan              | 5027241096 |

## Soal No 1

![image](https://github.com/user-attachments/assets/86dc4360-daf4-46ff-bfa2-e1dcd2f6446b)
- Mengecek apakah folder dengan path tertentu ada.
- stat() mengambil informasi tentang file.
- S_ISDIR() mengecek apakah itu folder.

![image](https://github.com/user-attachments/assets/30778217-303f-48b8-85dd-36154b769b84)
Callback yang dipakai CURL untuk menulis data hasil download ke file.

![image](https://github.com/user-attachments/assets/64323710-7266-4126-b3c6-5fec908900cb)
- Menggunakan libcurl untuk mendownload ZIP dari url dan menyimpannya sebagai out.
- Set CURLOPT_WRITEFUNCTION ke write_file dan CURLOPT_WRITEDATA ke FILE* yang terbuka.

![image](https://github.com/user-attachments/assets/8b28c58f-f762-46ef-be94-b13448c77d23)
1. Menggunakan libzip untuk membuka file .zip
2. Untuk setiap entri di ZIP:
- Jika entri adalah folder (diakhiri /), buat folder itu
- Jika file, buka dan tulis ke disk menggunakan buffer 1KB


1. Membuat folder Filtered2
2. Membaca isi folder Clues
3. Untuk setiap subfolder di Clues:
- Cek file reguler di dalamnya
- Jika file valid (<char>.txt), pindahkan ke Filtered
- Jika tidak valid, hapus
4. Valid artinya:
- Panjang nama 5
- Karakter pertama adalah digit atau huruf
- Diikuti ".txt"

![image](https://github.com/user-attachments/assets/251c5ed7-43c1-4e58-a894-956ba3fc39d5)
Mengecek apakah file diawali digit/huruf dan berakhiran .txt

![image](https://github.com/user-attachments/assets/ba16ca4c-049e-45fb-aaca-8a7abeff4f20)
Fungsi pembanding string untuk qsort

![image](https://github.com/user-attachments/assets/7602aca6-d7e2-4c8f-a366-fed13d234113)
![image](https://github.com/user-attachments/assets/7822b37e-13f8-49ae-bab6-968ae414908c)
- Membuka folder Filtered
- Mengumpulkan nama file digit (0.txt, 1.txt) dan huruf (a.txt, b.txt)
- Urutkan masing-masing
- Gabungkan ke Combined.txt dalam urutan bergantian: digit, huruf, digit, huruf...
- Isi file dibaca karakter per karakter, lalu file dihapus

![image](https://github.com/user-attachments/assets/89f145be-27b1-438c-9ef1-6af6d1244a57)
- Mengubah karakter huruf dengan algoritma ROT13
- ROT13: geser 13 huruf dalam alfabet, misalnya A -> N, N -> A

![image](https://github.com/user-attachments/assets/32dab234-6f5c-46b9-9b3a-75752738c39d)
- Membaca isi Combined.txt, mengaplikasikan ROT13, dan menyimpan hasil ke Decoded.txt

![image](https://github.com/user-attachments/assets/e6197d14-87d5-44ea-bda7-241f77a5f1ae)
### Jalankan dari:
```c
- ./action ➜ mendownload dan mengunzip()
```
```c
- ./action -m Filter ➜ panggil filter_files()
```
```c
- ./action -m Combine ➜ panggil combine_files()
```
```c
- ./action -m Decode ➜ panggil decode_file()
```

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

*1. void tulis_log(const char *aksi, const char *nama_file, int pid)*
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

*2. char dekripsi_base64(const char input)*
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

*3. void proses_daemon()*
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
*4. pid_t cari_pid_daemon()*
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

*5. void mulai_daemon()*
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

*6. void hentikan_daemon()*
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

*7. void pindahkan_file(const char dari, const char ke, const char aksi)*
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

*8. void hapus_semua_file()*
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

*9. int jalankan_program(char program, char args)*
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

*10. int perlu_download()*
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

*11. void unduh_starter_kit()*
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

*1. Cek jumlah argumen:*
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

*2. Cek apakah program decrypt sedang jalan:*
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

*3. Jalankan unduh_starter_kit() kecuali argumen --return:*
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

*4. Pilih aksi sesuai argumen:*
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

*5. Return sukses:*
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

### Deskripsi
DebugMon adalah program C yang berjalan di sistem Linux untuk memantau, menghentikan, atau memanipulasi proses milik user tertentu. Program ini juga bisa dijalankan sebagai daemon, mencatat log proses, dan bahkan memblokir akses user.

*Fitur Utama*
- Menampilkan semua proses yang dijalankan oleh user tertentu.
- Menjalankan daemon yang memantau proses secara berkala.
- Menghentikan daemon yang sedang berjalan.
- Mematikan semua proses dari user dan memblokir user tersebut.
- Mengembalikan akses shell user yang telah diblokir.
- Menyimpan log aktivitas pada file debugmon.log.

### Fungsi Kode

*1. log_action(process, status)*
```c
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
```
Mencatat aktivitas tertentu ke file log debugmon.log dengan format waktu dan status seperti RUNNING atau FAILED.

*2. get_user_processes(user, processes)*
```c
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
```
- Mengambil semua proses dari user tertentu:
- Membaca direktori /proc.
- Memeriksa UID dari proses dan mencocokkannya dengan user target.
- Mengambil nama proses, waktu CPU (utime + stime), dan memori (rss).Mengambil semua proses dari user tertentu:
- Membaca direktori /proc.
- Memeriksa UID dari proses dan mencocokkannya dengan user target.
- Mengambil nama proses, waktu CPU (utime + stime), dan memori (rss).

*3. list_processes(user)* 
```c
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
```
Menampilkan ke terminal semua proses user dengan PID, nama perintah, penggunaan CPU, dan penggunaan memori.
- Log akan dicatat sebagai list_STATUS(RUNNING).

*4. start_daemon(user)*
```c
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
```
Menjalankan program sebagai daemon:
- Forks proses dan menyimpannya ke file PID. 
- Setiap 5 detik, akan mencatat semua proses user ke file log.
- Output diarahkan ke /dev/null (background).

*5. stop_daemon(user)*
```c
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
```
Menghentikan daemon yang sedang berjalan:
- Membaca file /tmp/debugmon_daemon.pid untuk mendapatkan PID daemon.
- Mengirim sinyal SIGTERM ke daemon.

*6. fail_processes(user)*
```c
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
```
- Menghentikan semua proses user menggunakan SIGKILL.
- Setelah itu, mencoba memblokir akses user dengan mengganti shell menjadi /bin/false di file /etc/passwd.

*7. revert_changes(user)*
```c
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
```
Mengembalikan akses shell user dengan mengubah kembali field shell di /etc/passwd jika sebelumnya diubah ke /bin/false.

### Cara Jalanin

Kompilasi Program:
```c
gcc -o debugmon debugmon.c
```

Jalankan Program (sesuai perintah):
```c
./debugmon list <user>
```
Menampilkan semua proses milik user tertentu.
![image](https://github.com/user-attachments/assets/8fcd1f43-5a40-4446-be76-42e5d9fd796a)

```c
./debugmon daemon <user>
```
Menyalakan monitoring background (daemon). Bisa pantau proses real-time.
![image](https://github.com/user-attachments/assets/88dc2593-3bfd-43a2-9b2a-a51be2111b67)

```c
./debugmon stop <user>
```
Menghentikan monitoring daemon.
![image](https://github.com/user-attachments/assets/416458f7-08cf-4a57-a036-b7d2960b18ee)

```c
./debugmon fail <user>
```
Hati-hati! Kill semua proses milik user dan blokir user. Butuh akses root.
![image](https://github.com/user-attachments/assets/7eb1717c-fb8d-4df1-bab5-f1e55a87d08e)

```c
./debugmon revert <user>
```
Membuka blokir dan mengembalikan akses user seperti semula.
![image](https://github.com/user-attachments/assets/fdbdf594-2049-469c-b990-c27326fd6569)
