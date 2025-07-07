#define _CRT_SECURE_NO_DEPRECATE
#include <stdio.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdlib.h>

#define PASSWORD_LIST_FILE "HW1/10-million-password-list-top-1000000.txt"
#define OUTPUT_FILE "HW1/pass_SHA1.txt"
#define SHA1_DIGEST_LENGTH 20

// Function to compute SHA-1 hash and return it as a hex string
void compute_sha1(unsigned char* data, size_t len, unsigned char* output)
{
    SHA_CTX sha_ctx;  // Use SHA_CTX for SHA-1 context in OpenSSL
    SHA1_Init(&sha_ctx);
    SHA1_Update(&sha_ctx, data, len);
    SHA1_Final(output, &sha_ctx);
}

// Function to print SHA-1 hash in hex format
void print_sha1_hex(unsigned char* hash, FILE* out_file)
{
    for (int i = 0; i < SHA1_DIGEST_LENGTH; i++) {
        fprintf(out_file, "%02x", hash[i]);
    }
    fprintf(out_file, "\n");
}

int main()
{
    FILE* input_file = fopen(PASSWORD_LIST_FILE, "r");
    FILE* output_file = fopen(OUTPUT_FILE, "w");

    if (!input_file || !output_file) {
        printf("Error opening files.\n");
        return 1;
    }

    unsigned char target_hash[SHA1_DIGEST_LENGTH] = { 0x2e, 0x1a, 0x48, 0x06, 0x70, 0xe3, 0x1a, 0x5d, 0x01, 0x5e, 0x28, 0xde, 0x04, 0x31, 0x36, 0xb6, 0x2e, 0x76, 0x2d, 0x29 };
    char password[256];
    unsigned char hash[SHA1_DIGEST_LENGTH];

    // Read each password line-by-line
    while (fgets(password, sizeof(password), input_file)) {
        // Remove the newline character at the end of the password
        size_t len = strlen(password);
        if (password[len - 1] == '\n') {
            password[len - 1] = '\0';
        }

        // Compute SHA-1 hash
        compute_sha1((unsigned char*)password, strlen(password), hash);

        // Check if the hash matches the target hash
        if (memcmp(hash, target_hash, SHA1_DIGEST_LENGTH) == 0) {
            printf("Found password: %s\n", password);  // Print the password
        }

        // Write the SHA-1 hash in hex to the output file
        print_sha1_hex(hash, output_file);
    }

    fclose(input_file);
    fclose(output_file);

    printf("Process completed. SHA-1 hashes are saved in %s.\n", OUTPUT_FILE);
    return 0;
}

//1. Identify the clear password having the SHA - 1 message digest as
//2e1a480670e31a5d015e28de043136b62e762d29(as hex binary representation).
// The clear password will be printed into the Console Application.
// The passwords stored by the file must be treated as binary input for 
// the message digest algorithm.

//2. Create an output text file(pass_SHA1.txt) containing the all SHA - 1 
// message digests in hex representation(all hex pairs contain the both 
// letters).Each line of the output file corresponds to the clear password 
// placed on the same line in the 10-million-password-list-top-1000000.txt.
