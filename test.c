#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define FILE_NAME "contacts.enc"
#define MAX_LEN 1024
#define AES_KEYLEN 32     // 256-bit key
#define AES_BLOCK_SIZE 16 // 128-bit block

#define USERNAME "anonymous"

// Cross-platform hidden password input
#ifdef _WIN32
#include <conio.h>
void getHiddenPassword(char *pass) {
    int i = 0; char ch;
    while ((ch = _getch()) != '\r') {
        if (ch == '\b' && i > 0) { i--; printf("\b \b"); }
        else if (ch != '\b') { pass[i++] = ch; printf("*"); }
    }
    pass[i] = '\0';
}
#else
#include <termios.h>
#include <unistd.h>
void getHiddenPassword(char *pass) {
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt; newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    scanf("%s", pass);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
}
#endif

// Key derivation: SHA-256 of password
void deriveKey(const char *password, unsigned char *key) {
    SHA256((unsigned char*)password, strlen(password), key);
}

// AES Encryption
int encrypt(const unsigned char *plaintext, int plaintext_len,
            const unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// AES Decryption
int decrypt(const unsigned char *ciphertext, int ciphertext_len,
            const unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;
    plaintext[plaintext_len] = '\0';
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

// Authenticate user
void authenticate(char *runtimePassword) {
    char inputUser[50];

    printf("Enter Username: ");
    fgets(inputUser, sizeof(inputUser), stdin);
    inputUser[strcspn(inputUser, "\n")] = '\0';

    printf("Enter Password: ");
    getHiddenPassword(runtimePassword);
    printf("\n");

    if (strcmp(inputUser, USERNAME) != 0) {
        printf("Access Denied! Invalid Credentials.\n");
        exit(1);
    }

    printf("Login Successful!\n");
}

// Write contact with IV + length + ciphertext
void addContact(const unsigned char *key) {
    char name[50], mobile[15], email[50], contactString[MAX_LEN];
    unsigned char iv[AES_BLOCK_SIZE], ciphertext[MAX_LEN];
    int ciphertext_len;

    printf("Enter Name: "); scanf("%s", name);
    printf("Enter Mobile: "); scanf("%s", mobile);
    printf("Enter Email: "); scanf("%s", email);

    snprintf(contactString, sizeof(contactString), "%s %s %s", name, mobile, email);

    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) { printf("Error generating IV!\n"); return; }

    ciphertext_len = encrypt((unsigned char*)contactString, strlen(contactString), key, iv, ciphertext);

    FILE *file = fopen(FILE_NAME, "ab");
    if (!file) { printf("Error opening file!\n"); return; }

    fwrite(iv, 1, AES_BLOCK_SIZE, file);
    fwrite(&ciphertext_len, sizeof(int), 1, file);
    fwrite(ciphertext, 1, ciphertext_len, file);
    fclose(file);

    printf("Contact saved successfully!\n");
}

// Read one contact from file
int readContact(FILE *file, unsigned char *iv, unsigned char *ciphertext) {
    int ciphertext_len;
    if (fread(iv, 1, AES_BLOCK_SIZE, file) != AES_BLOCK_SIZE) return 0;
    if (fread(&ciphertext_len, sizeof(int), 1, file) != 1) return 0;
    if (fread(ciphertext, 1, ciphertext_len, file) != ciphertext_len) return 0;
    return ciphertext_len;
}

// Search contact
void searchContact(const unsigned char *key) {
    FILE *file = fopen(FILE_NAME, "rb");
    if (!file) { printf("Error opening file!\n"); return; }

    char searchName[50]; unsigned char iv[AES_BLOCK_SIZE], ciphertext[MAX_LEN], plaintext[MAX_LEN];
    int ciphertext_len; int found = 0;

    printf("Enter name to search: "); scanf("%s", searchName);

    while ((ciphertext_len = readContact(file, iv, ciphertext))) {
        if (decrypt(ciphertext, ciphertext_len, key, iv, plaintext) < 0) continue;
        char name[50], mobile[15], email[50];
        if (sscanf((char*)plaintext, "%s %s %s", name, mobile, email) == 3) {
            if (strcmp(name, searchName) == 0) {
                printf("\nContact Found:\nName: %s\nMobile: %s\nEmail: %s\n", name, mobile, email);
                found = 1; break;
            }
        }
    }

    if (!found) printf("Contact not found!\n");
    fclose(file);
}

// Delete contact
void deleteContact(const unsigned char *key) {
    FILE *file = fopen(FILE_NAME, "rb");
    if (!file) { printf("Error opening file!\n"); return; }

    FILE *temp = fopen("temp.enc", "wb");
    if (!temp) { fclose(file); printf("Error!\n"); return; }

    char searchName[50]; unsigned char iv[AES_BLOCK_SIZE], ciphertext[MAX_LEN], plaintext[MAX_LEN];
    int ciphertext_len; int found = 0;

    printf("Enter name to delete: "); scanf("%s", searchName);

    while ((ciphertext_len = readContact(file, iv, ciphertext))) {
        if (decrypt(ciphertext, ciphertext_len, key, iv, plaintext) < 0) continue;
        char name[50], mobile[15], email[50];
        if (sscanf((char*)plaintext, "%s %s %s", name, mobile, email) == 3) {
            if (strcmp(name, searchName) == 0) { found = 1; continue; }
        }
        fwrite(iv, 1, AES_BLOCK_SIZE, temp);
        fwrite(&ciphertext_len, sizeof(int), 1, temp);
        fwrite(ciphertext, 1, ciphertext_len, temp);
    }

    fclose(file);
    fclose(temp);

    remove(FILE_NAME);
    rename("temp.enc", FILE_NAME);

    if (found) printf("Contact deleted successfully!\n");
    else printf("Contact not found!\n");
}

// Edit contact
void editContact(const unsigned char *key) {
    deleteContact(key);
    printf("Enter new details:\n");
    addContact(key);
}

// Main
int main() {
    char runtimePassword[128];
    authenticate(runtimePassword);

    unsigned char key[AES_KEYLEN];
    deriveKey(runtimePassword, key);

    int choice;
    while (1) {
        printf("\n1. Add Contact\n2. Search Contact\n3. Delete Contact\n4. Edit Contact\n5. Exit\nEnter choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1: addContact(key); break;
            case 2: searchContact(key); break;
            case 3: deleteContact(key); break;
            case 4: editContact(key); break;
            case 5: printf("Exiting...\n"); return 0;
            default: printf("Invalid choice!\n");
        }
    }
}
