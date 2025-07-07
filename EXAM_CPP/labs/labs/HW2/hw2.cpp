#define _CRT_SECURE_NO_DEPRECATE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define MAX_BUFFER_SIZE 1024
#define AES_BLOCK_SIZE 16

// Function to read the file into a buffer
unsigned char* read_file(const char* filename, size_t* len)
{
    FILE* file = fopen(filename, "rb");
    if (!file)
    {
        perror("Unable to open file");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *len = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char* buffer = (unsigned char*)malloc(*len);
    if (!buffer)
    {
        perror("Memory allocation failed");
        fclose(file);
        return NULL;
    }

    fread(buffer, 1, *len, file);
    fclose(file);
    return buffer;
}

// Function to perform AES-ECB encryption
void aes_ecb_encrypt(const unsigned char* input, size_t length, const unsigned char* key, unsigned char* output)
{
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);  // 128-bit AES key (can be 128, 192, or 256)

    size_t i;
    for (i = 0; i < length; i += AES_BLOCK_SIZE)
    {
        AES_ecb_encrypt(input + i, output + i, &aes_key, AES_ENCRYPT);
    }
}

// Function to print data in hexadecimal format
void print_hex(FILE* file, const unsigned char* data, size_t length)
{
    for (size_t i = 0; i < length; i++)
    {
        fprintf(file, "%02x", data[i]);
    }
    fprintf(file, "\n");
}

int main()
{
    // Read the AES key from file
    size_t key_len;
    unsigned char* aes_key = read_file("HW2/pass.key", &key_len);
    if (aes_key == NULL || key_len != AES_BLOCK_SIZE)
    {
        printf("Error reading AES key (must be 16 bytes).\n");
        return 1;
    }

    // Read the input file (Accounts.txt) to get the accounts
    size_t accounts_len;
    unsigned char* accounts_data = read_file("HW2/Accounts.txt", &accounts_len);
    if (accounts_data == NULL)
    {
        return 1;
    }

    // Prepare the output file (SHA256_Enc.txt)
    FILE* output_file = fopen("HW2/SHA256_Enc.txt", "w");
    if (!output_file)
    {
        perror("Unable to open output file");
        free(aes_key);
        free(accounts_data);
        return 1;
    }

    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];

    // Process each line in Accounts.txt
    size_t i = 0;
    while (i < accounts_len)
    {
        size_t line_start = i;

        // Find the next newline or end of file
        while (i < accounts_len && accounts_data[i] != '\n')
        {
            i++;
        }

        size_t line_len = i - line_start;
        if (line_len > 0)
        {
            // Hash the current line (account) using SHA-256
            SHA256_CTX sha256_ctx;
            SHA256_Init(&sha256_ctx);
            SHA256_Update(&sha256_ctx, accounts_data + line_start, line_len);
            SHA256_Final(sha256_hash, &sha256_ctx);

            // Encrypt the SHA-256 hash using AES-ECB
            unsigned char encrypted_hash[SHA256_DIGEST_LENGTH];
            aes_ecb_encrypt(sha256_hash, SHA256_DIGEST_LENGTH, aes_key, encrypted_hash);

            // Write the encrypted hash to the output file in hex format
            print_hex(output_file, encrypted_hash, SHA256_DIGEST_LENGTH);
        }

        // Move to the next line
        if (i < accounts_len && accounts_data[i] == '\n')
        {
            i++;
        }
    }

    // Clean up and close files
    fclose(output_file);
    free(aes_key);
    free(accounts_data);

    printf("Encryption completed successfully.\n");
    return 0;
}

//1. Perform AES - ECB encryption of the SHA - 256 messages as binary 
// representation extracted from the file Accounts.txt.
// The AES key is stored by the file pass.key and it will be used as 
// binary content of the AES key file.

//2. Save each encrypted SHA - 256 message into a text file called 
// SHA256_Enc.txt as hex representation where each line contains 
// one single SHA - 256 encrypted message for the corresponding 
// line in Accounts.txt.
