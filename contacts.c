#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define FILE_NAME "contacts.txt"
#define MAX_LEN 1024

// Hardcoded username and password
#define USERNAME "enp7s0"
#define PASSWORD "infected"

// Base64 Encoding Table
const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Function to encode a string into Base64
void base64_encode(const char *input, char *output) {
    int i, j, len = strlen(input);
    int val = 0, valb = -6;

    for (i = 0, j = 0; i < len; i++) {
        val = (val << 8) | (unsigned char)input[i];
        valb += 8;
        while (valb >= 0) {
            output[j++] = base64_table[(val >> valb) & 0x3F];
            valb -= 6;
        }
    }
    if (valb > -6) output[j++] = base64_table[((val << 8) >> (valb + 8)) & 0x3F];
    while (j % 4) output[j++] = '='; // Padding
    output[j] = '\0';
}

// Function to find Base64 character index
int base64_index(char c) {
    char *ptr = strchr(base64_table, c);
    return ptr ? (int)(ptr - base64_table) : -1;
}

// Function to decode a Base64 string
void base64_decode(const char *input, char *output) {
    int i, j, len = strlen(input);
    int val = 0, valb = -8;

    for (i = 0, j = 0; i < len; i++) {
        if (input[i] == '=' || base64_index(input[i]) == -1) continue;
        val = (val << 6) | base64_index(input[i]);
        valb += 6;
        if (valb >= 0) {
            output[j++] = (val >> valb) & 0xFF;
            valb -= 8;
        }
    }
    output[j] = '\0';
}

// Function to authenticate user
void authenticate() {
    char inputUser[50], inputPass[50];

    printf("Enter Username: ");
    scanf("%s", inputUser);
    printf("Enter Password: ");
    scanf("%s", inputPass);

    if (strcmp(inputUser, USERNAME) != 0 || strcmp(inputPass, PASSWORD) != 0) {
        printf("Access Denied! Invalid Credentials.\n");
        exit(1);
    }
    printf("Login Successful!\n");
}

// Function to add a new contact
void addContact() {
    char name[50], mobile[15], email[50], contactString[MAX_LEN], encodedContact[MAX_LEN];

    printf("Enter Name: ");
    scanf("%s", name);
    printf("Enter Mobile: ");
    scanf("%s", mobile);
    printf("Enter Email: ");
    scanf("%s", email);

    snprintf(contactString, sizeof(contactString), "%s %s %s", name, mobile, email);
    
    base64_encode(contactString, encodedContact);

    FILE *file = fopen(FILE_NAME, "a");
    if (file == NULL) {
        printf("Error opening file!\n");
        return;
    }
    fprintf(file, "%s\n", encodedContact);
    fclose(file);

    printf("Contact saved successfully!\n");
}

// Function to search for a contact
void searchContact() {
    FILE *file = fopen(FILE_NAME, "r");
    if (file == NULL) {
        printf("Error opening file!\n");
        return;
    }

    char searchName[50], encodedLine[MAX_LEN], decodedLine[MAX_LEN];
    int found = 0;

    printf("Enter name to search: ");
    scanf("%s", searchName);

    while (fgets(encodedLine, sizeof(encodedLine), file)) {
        encodedLine[strcspn(encodedLine, "\n")] = 0;

        base64_decode(encodedLine, decodedLine);

        char name[50], mobile[15], email[50];
        if (sscanf(decodedLine, "%s %s %s", name, mobile, email) == 3) {
            if (strcmp(name, searchName) == 0) {
                printf("\nContact Found:\n");
                printf("Name: %s\nMobile: %s\nEmail: %s\n", name, mobile, email);
                found = 1;
                break;
            }
        }
    }

    if (!found) {
        printf("\nContact not found!\n");
    }

    fclose(file);
}

// Function to delete a contact
void deleteContact() {
    FILE *file = fopen(FILE_NAME, "r");
    if (file == NULL) {
        printf("Error opening file!\n");
        return;
    }

    char searchName[50], encodedLine[MAX_LEN], decodedLine[MAX_LEN];
    char tempFile[] = "temp.txt";
    FILE *temp = fopen(tempFile, "w");
    int found = 0;

    printf("Enter name to delete: ");
    scanf("%s", searchName);

    while (fgets(encodedLine, sizeof(encodedLine), file)) {
        encodedLine[strcspn(encodedLine, "\n")] = 0;
        base64_decode(encodedLine, decodedLine);

        char name[50], mobile[15], email[50];
        if (sscanf(decodedLine, "%s %s %s", name, mobile, email) == 3) {
            if (strcmp(name, searchName) == 0) {
                found = 1;
                continue; // Skip writing this contact
            }
        }
        fprintf(temp, "%s\n", encodedLine);
    }

    fclose(file);
    fclose(temp);

    remove(FILE_NAME);
    rename(tempFile, FILE_NAME);

    if (found)
        printf("Contact deleted successfully!\n");
    else
        printf("Contact not found!\n");
}

// Function to edit a contact
void editContact() {
    deleteContact();
    printf("Enter new details for the contact:\n");
    addContact();
}

// Main function
int main() {
    authenticate(); // Authenticate user before execution

    int choice;

    while (1) {
        printf("\n1. Add Contact\n2. Search Contact\n3. Delete Contact\n4. Edit Contact\n5. Exit\nEnter choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1: addContact(); break;
            case 2: searchContact(); break;
            case 3: deleteContact(); break;
            case 4: editContact(); break;
            case 5: printf("Exiting...\n"); return 0;
            default: printf("Invalid choice! Try again.\n");
        }
    }
}

