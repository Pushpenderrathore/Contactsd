// contacts_secure.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

// === Config ===
#define FILE_NAME "contacts.enc"
#define MAX_PLAINTEXT 1024
#define SALT_SIZE 16
#define IV_SIZE 12
#define TAG_SIZE 16
#define KEY_SIZE 32
#define PBKDF2_ITERS 150000
#define USERNAME "anonymous"

// === Utility: hide password input ===
void getHiddenPassword(char *pass, size_t max_len) {
#ifdef _WIN32
    size_t i = 0; int ch;
    while ((ch = _getch()) != '\r' && i + 1 < max_len) {
        if (ch == '\b') { if (i > 0) { i--; printf("\b \b"); } }
        else { pass[i++] = (char)ch; printf("*"); }
    }
    pass[i] = '\0';
#else
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt; newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    if (fgets(pass, (int)max_len, stdin) == NULL) pass[0] = '\0';
    pass[strcspn(pass, "\n")] = '\0';
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
}

// === KDF: PBKDF2-HMAC-SHA256 ===
int derive_key_pbkdf2(const char *password, const unsigned char *salt, unsigned char *out_key) {
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password),
                           salt, SALT_SIZE,
                           PBKDF2_ITERS,
                           EVP_sha256(),
                           KEY_SIZE, out_key)) {
        return 0;
    }
    return 1;
}

// === AES-GCM encrypt/decrypt ===
int aes_gcm_encrypt(const unsigned char *plaintext, int plaintext_len,
                    const unsigned char *key,
                    const unsigned char *iv, int iv_len,
                    unsigned char *ciphertext,
                    unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, ciphertext_len = 0, ret = -1;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto done;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto done;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) goto done;
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) goto done;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) goto done;
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) goto done;
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag)) goto done;

    ret = ciphertext_len;

done:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int aes_gcm_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                    const unsigned char *key,
                    const unsigned char *iv, int iv_len,
                    const unsigned char *tag,
                    unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, plaintext_len = 0, ret = -1;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto done;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto done;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) goto done;
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) goto done;

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) goto done;
    plaintext_len = len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void *)tag)) goto done;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        ret = -2; // auth fail
        goto done;
    }
    plaintext_len += len;
    ret = plaintext_len;

done:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

// === Read/write helpers ===
void write_int32(FILE *f, int32_t v) { fwrite(&v, sizeof(int32_t), 1, f); }
int read_int32(FILE *f, int32_t *out) { return fread(out, sizeof(int32_t), 1, f) == 1; }

// === Add contact (salt|iv|tag|ct_len|ciphertext) ===
void addContact(const char *masterPassword) {
    char name[128], mobile[64], email[128];
    unsigned char salt[SALT_SIZE], iv[IV_SIZE], tag[TAG_SIZE];
    unsigned char key[KEY_SIZE];
    unsigned char plaintext[MAX_PLAINTEXT];
    unsigned char ciphertext[MAX_PLAINTEXT + 128];
    int plaintext_len, ct_len;

    printf("Enter Name: "); if (scanf("%127s", name) != 1) return;
    printf("Enter Mobile: "); if (scanf("%63s", mobile) != 1) return;
    printf("Enter Email: "); if (scanf("%127s", email) != 1) return;

    plaintext_len = snprintf((char*)plaintext, sizeof(plaintext), "%s %s %s", name, mobile, email);
    if (plaintext_len <= 0) { printf("Error preparing plaintext\n"); return; }

    if (1 != RAND_bytes(salt, SALT_SIZE)) { printf("RAND_bytes(salt) failed\n"); return; }
    if (!derive_key_pbkdf2(masterPassword, salt, key)) { printf("KDF failed\n"); return; }

    if (1 != RAND_bytes(iv, IV_SIZE)) { printf("RAND_bytes(iv) failed\n"); OPENSSL_cleanse(key, KEY_SIZE); return; }

    ct_len = aes_gcm_encrypt(plaintext, plaintext_len, key, iv, IV_SIZE, ciphertext, tag);
    OPENSSL_cleanse(key, KEY_SIZE);
    if (ct_len < 0) { printf("Encryption failed\n"); return; }

    FILE *f = fopen(FILE_NAME, "ab");
    if (!f) { perror("fopen"); return; }

    fwrite(salt, 1, SALT_SIZE, f);
    fwrite(iv, 1, IV_SIZE, f);
    fwrite(tag, 1, TAG_SIZE, f);
    write_int32(f, ct_len);
    fwrite(ciphertext, 1, ct_len, f);
    fclose(f);

    printf("Contact saved successfully!\n");
}

// === Read single record; returns ciphertext_len or 0 on EOF/error ===
int read_record(FILE *f, unsigned char *salt, unsigned char *iv, unsigned char *tag, unsigned char *ciphertext) {
    int32_t ct_len;
    if (fread(salt, 1, SALT_SIZE, f) != SALT_SIZE) return 0;
    if (fread(iv, 1, IV_SIZE, f) != IV_SIZE) return 0;
    if (fread(tag, 1, TAG_SIZE, f) != TAG_SIZE) return 0;
    if (!read_int32(f, &ct_len)) return 0;
    if (ct_len <= 0 || ct_len > MAX_PLAINTEXT + 128) return 0;
    if (fread(ciphertext, 1, ct_len, f) != (size_t)ct_len) return 0;
    return ct_len;
}

// === Search ===
void searchContact(const char *masterPassword) {
    char searchName[128];
    unsigned char salt[SALT_SIZE], iv[IV_SIZE], tag[TAG_SIZE], key[KEY_SIZE];
    unsigned char ciphertext[MAX_PLAINTEXT + 128], plaintext[MAX_PLAINTEXT];
    int ct_len;
    int found = 0;

    printf("Enter name to search: ");
    if (scanf("%127s", searchName) != 1) return;

    FILE *f = fopen(FILE_NAME, "rb");
    if (!f) { printf("No contacts file or error opening file\n"); return; }

    while ((ct_len = read_record(f, salt, iv, tag, ciphertext)) > 0) {
        if (!derive_key_pbkdf2(masterPassword, salt, key)) continue;
        int p_len = aes_gcm_decrypt(ciphertext, ct_len, key, iv, IV_SIZE, tag, plaintext);
        OPENSSL_cleanse(key, KEY_SIZE);
        if (p_len < 0) continue; // auth failed -> skip
        plaintext[p_len] = '\0';
        char name[128], mobile[64], email[128];
        if (sscanf((char*)plaintext, "%127s %63s %127s", name, mobile, email) == 3) {
            if (strcmp(name, searchName) == 0) {
                printf("\nContact Found:\nName: %s\nMobile: %s\nEmail: %s\n", name, mobile, email);
                found = 1;
                break;
            }
        }
    }

    if (!found) printf("Contact not found!\n");
    fclose(f);
}

// === Delete ===
void deleteContact(const char *masterPassword) {
    char searchName[128];
    unsigned char salt[SALT_SIZE], iv[IV_SIZE], tag[TAG_SIZE], key[KEY_SIZE];
    unsigned char ciphertext[MAX_PLAINTEXT + 128], plaintext[MAX_PLAINTEXT];
    int ct_len;
    int found = 0;

    printf("Enter name to delete: ");
    if (scanf("%127s", searchName) != 1) return;

    FILE *f = fopen(FILE_NAME, "rb");
    if (!f) { printf("No contacts file or error opening file\n"); return; }
    FILE *tmp = fopen("temp.enc", "wb");
    if (!tmp) { fclose(f); printf("Cannot create temp file\n"); return; }

    while ((ct_len = read_record(f, salt, iv, tag, ciphertext)) > 0) {
        if (!derive_key_pbkdf2(masterPassword, salt, key)) {
            // write back unchanged to avoid data loss
            fwrite(salt,1,SALT_SIZE,tmp); fwrite(iv,1,IV_SIZE,tmp); fwrite(tag,1,TAG_SIZE,tmp);
            write_int32(tmp, ct_len); fwrite(ciphertext,1,ct_len,tmp);
            continue;
        }
        int p_len = aes_gcm_decrypt(ciphertext, ct_len, key, iv, IV_SIZE, tag, plaintext);
        OPENSSL_cleanse(key, KEY_SIZE);
        if (p_len < 0) {
            // cannot decrypt: keep record (tampered or wrong password)
            fwrite(salt,1,SALT_SIZE,tmp); fwrite(iv,1,IV_SIZE,tmp); fwrite(tag,1,TAG_SIZE,tmp);
            write_int32(tmp, ct_len); fwrite(ciphertext,1,ct_len,tmp);
            continue;
        }
        plaintext[p_len] = '\0';
        char name[128], mobile[64], email[128];
        if (sscanf((char*)plaintext, "%127s %63s %127s", name, mobile, email) == 3) {
            if (strcmp(name, searchName) == 0) { found = 1; continue; } // skip (delete)
        }
        // write back
        fwrite(salt,1,SALT_SIZE,tmp); fwrite(iv,1,IV_SIZE,tmp); fwrite(tag,1,TAG_SIZE,tmp);
        write_int32(tmp, ct_len); fwrite(ciphertext,1,ct_len,tmp);
    }

    fclose(f); fclose(tmp);

    if (remove(FILE_NAME) != 0) perror("remove");
    if (rename("temp.enc", FILE_NAME) != 0) perror("rename");

    if (found) printf("Contact deleted successfully!\n");
    else printf("Contact not found!\n");
}

// === Edit ===
void editContact(const char *masterPassword) {
    deleteContact(masterPassword);
    printf("Enter new details for this contact:\n");
    addContact(masterPassword);
}

// === Authenticate ===
void authenticate(char *runtimePassword, size_t max_len) {
    char inputUser[64];
    printf("Enter Username: ");
    if (fgets(inputUser, sizeof(inputUser), stdin) == NULL) exit(1);
    inputUser[strcspn(inputUser, "\n")] = '\0';

    printf("Enter Password: ");
    getHiddenPassword(runtimePassword, max_len);
    printf("\n");

    if (strcmp(inputUser, USERNAME) != 0) {
        printf("Access Denied! Invalid Username.\n");
        exit(1);
    }
    printf("Login Successful!\n");
}

// === main ===
int main(void) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    char runtimePassword[256];
    authenticate(runtimePassword, sizeof(runtimePassword));

    int choice;
    while (1) {
        printf("\n1. Add Contact\n2. Search Contact\n3. Delete Contact\n4. Edit Contact\n5. Exit\nEnter choice: ");
        if (scanf("%d", &choice) != 1) {
            int c; while ((c = getchar()) != '\n' && c != EOF) {}
            continue;
        }

        switch (choice) {
            case 1: addContact(runtimePassword); break;
            case 2: searchContact(runtimePassword); break;
            case 3: deleteContact(runtimePassword); break;
            case 4: editContact(runtimePassword); break;
            case 5: printf("Exiting...\n"); OPENSSL_cleanse(runtimePassword, sizeof(runtimePassword)); return 0;
            default: printf("Invalid choice!\n");
        }
    }
    return 0;
}
