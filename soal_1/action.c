#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <curl/curl.h>
#include <zip.h>

#define ZIP_URL "https://drive.google.com/uc?export=download&id=1xFn1OBJUuSdnApDseEczKhtNzyGekauK"
#define ZIP_NAME "Clues.zip"
#define CLUES_FOLDER "Clues"
#define FILTERED_FOLDER "Filtered"
#define COMBINED_FILE "Combined.txt"
#define DECODED_FILE "Decoded.txt"

int folder_exists(const char *path) {
    struct stat st = {0};
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

size_t write_file(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    return fwrite(ptr, size, nmemb, stream);
}

int download_zip(const char *url, const char *out) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    FILE *fp = fopen(out, "wb");
    if (!fp) return 0;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_file);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    fclose(fp);

    return res == CURLE_OK;
}

int extract_zip(const char *zipname) {
    int err = 0;
    zip_t *za = zip_open(zipname, 0, &err);
    if (!za) return 0;

    zip_int64_t count = zip_get_num_entries(za, 0);
    for (zip_int64_t i = 0; i < count; i++) {
        const char *name = zip_get_name(za, i, 0);
        if (!name) continue;

        char outpath[512];
        snprintf(outpath, sizeof(outpath), "%s", name);

        if (name[strlen(name) - 1] == '/') {
            mkdir(outpath, 0755);
            continue;
        }

        zip_file_t *zf = zip_fopen_index(za, i, 0);
        if (!zf) continue;

        FILE *fout = fopen(outpath, "wb");
        if (!fout) {
            zip_fclose(zf);
            continue;
        }

        char buf[1024];
        zip_int64_t len;
        while ((len = zip_fread(zf, buf, sizeof(buf))) > 0) {
            fwrite(buf, 1, len, fout);
        }

        fclose(fout);
        zip_fclose(zf);
    }

    zip_close(za);
    return 1;
}

void filter_files() {
    mkdir(FILTERED_FOLDER, 0755);

    DIR *root = opendir(CLUES_FOLDER);
    if (!root) return;

    struct dirent *entry;
    while ((entry = readdir(root)) != NULL) {
        if (entry->d_type != DT_DIR || strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char subpath[512];
        snprintf(subpath, sizeof(subpath), "%s/%s", CLUES_FOLDER, entry->d_name);
        DIR *subdir = opendir(subpath);
        if (!subdir) continue;

        struct dirent *file;
        while ((file = readdir(subdir)) != NULL) {
            if (file->d_type != DT_REG) continue;

            char *name = file->d_name;
            int len = strlen(name);

            if (len == 5 && name[1] == '.' && strcmp(&name[2], "txt") == 0 &&
                (isalpha(name[0]) || isdigit(name[0]))) {
                char src[512], dest[512];
                snprintf(src, sizeof(src), "%s/%s", subpath, name);
                snprintf(dest, sizeof(dest), "%s/%s", FILTERED_FOLDER, name);
                rename(src, dest);
            } else {
                char del[512];
                snprintf(del, sizeof(del), "%s/%s", subpath, name);
                remove(del);
            }
        }
        closedir(subdir);
    }

    closedir(root);
    printf("File valid dipindah ke folder Filtered.\n");
}

int is_digit_file(const char *name) {
    return isdigit(name[0]) && strcmp(&name[1], ".txt") == 0;
}

int is_alpha_file(const char *name) {
    return isalpha(name[0]) && strcmp(&name[1], ".txt") == 0;
}

int name_compare(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

void combine_files() {
    DIR *dir = opendir(FILTERED_FOLDER);
    if (!dir) {
        printf("Folder Filtered tidak ditemukan.\n");
        return;
    }

    char *digits[100], *alphas[100];
    int d_count = 0, a_count = 0;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_REG) continue;

        if (is_digit_file(entry->d_name)) {
            digits[d_count++] = strdup(entry->d_name);
        } else if (is_alpha_file(entry->d_name)) {
            alphas[a_count++] = strdup(entry->d_name);
        }
    }
    closedir(dir);

    qsort(digits, d_count, sizeof(char *), name_compare);
    qsort(alphas, a_count, sizeof(char *), name_compare);

    FILE *out = fopen(COMBINED_FILE, "w");
    if (!out) {
        printf("Gagal membuat Combined.txt\n");
        return;
    }

    int i = 0, j = 0;
    while (i < d_count || j < a_count) {
        if (i < d_count) {
            char path[256];
            snprintf(path, sizeof(path), "%s/%s", FILTERED_FOLDER, digits[i]);
            FILE *fp = fopen(path, "r");
            if (fp) {
                char c;
                while ((c = fgetc(fp)) != EOF) fputc(c, out);
                fclose(fp);
                remove(path);
            }
            free(digits[i]);
            i++;
        }

        if (j < a_count) {
            char path[256];
            snprintf(path, sizeof(path), "%s/%s", FILTERED_FOLDER, alphas[j]);
            FILE *fp = fopen(path, "r");
            if (fp) {
                char c;
                while ((c = fgetc(fp)) != EOF) fputc(c, out);
                fclose(fp);
                remove(path);
            }
            free(alphas[j]);
            j++;
        }
    }

    fclose(out);
    printf("File digabung ke Combined.txt dengan urutan angka-huruf.\n");
}

char rot13(char c) {
    if (c >= 'a' && c <= 'z') return 'a' + (c - 'a' + 13) % 26;
    if (c >= 'A' && c <= 'Z') return 'A' + (c - 'A' + 13) % 26;
    return c;
}

void decode_file() {
    FILE *in = fopen(COMBINED_FILE, "r");
    if (!in) {
        printf("Combined.txt tidak ditemukan.\n");
        return;
    }

    FILE *out = fopen(DECODED_FILE, "w");
    if (!out) {
        fclose(in);
        printf("Gagal membuat Decoded.txt\n");
        return;
    }

    char c;
    while ((c = fgetc(in)) != EOF) {
        fputc(rot13(c), out);
    }

    fclose(in);
    fclose(out);
    printf("File berhasil didekode ke Decoded.txt\n");
}

int main(int argc, char *argv[]) {
    if (argc == 3 && strcmp(argv[1], "-m") == 0) {
        if (strcmp(argv[2], "Filter") == 0) {
            filter_files();
            return 0;
        } else if (strcmp(argv[2], "Combine") == 0) {
            combine_files();
            return 0;
        } else if (strcmp(argv[2], "Decode") == 0) {
            decode_file();
            return 0;
        }
    }

    if (!folder_exists(CLUES_FOLDER)) {
        printf("Mendownload Clues.zip...\n");
        if (!download_zip(ZIP_URL, ZIP_NAME)) {
            printf("Gagal mendownload zip.\n");
            return 1;
        }

        printf("Mengekstrak zip...\n");
        if (!extract_zip(ZIP_NAME)) {
            printf("Gagal ekstraksi zip.\n");
            return 1;
        }

        remove(ZIP_NAME);
    } else {
        printf("Folder Clues sudah ada.\n");
    }

    printf("Usage: ./action -m [Filter|Combine|Decode]\n");
    return 0;
}
