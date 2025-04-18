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

2. 

## Soal No 3

## Soal No 4
