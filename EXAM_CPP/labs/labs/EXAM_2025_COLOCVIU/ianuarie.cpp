#define _CRT_SECURE_NO_DEPRECATE
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/applink.c>

// Constants
#define AES_KEY_SIZE 16 // 128 bits for AES
#define SHA256_DIGEST_LENGTH 32 // SHA-256 size
#define RSA_KEY_SIZE 2048
#define RSA_PEM_SIZE 887
#define BUFFER_SIZE 1024

// Helper function for reading a file into a buffer
size_t read_file(const char* filename, unsigned char** buffer) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        return 0;
    }
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    *buffer = (unsigned char*)malloc(file_size);
    if (!*buffer) {
        perror("Memory allocation failed");
        fclose(file);
        return 0;
    }

    fread(*buffer, 1, file_size, file);
    fclose(file);

    return file_size;
}

// Sign data using RSA private key and SHA-256
int sign_data(RSA* rsa, unsigned char* data, size_t data_len, unsigned char** signature, unsigned int* sig_len) {
    *sig_len = RSA_size(rsa);
    *signature = (unsigned char*)malloc(*sig_len);
    if (!*signature) {
        perror("Memory allocation failed for signature");
        return -1;
    }

    return RSA_sign(NID_sha256, data, data_len, *signature, sig_len, rsa);
}

// Encrypt data using AES-ECB
int encrypt_aes_ecb(unsigned char* key, unsigned char* input, size_t input_len, unsigned char** output) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);

    size_t output_len = (input_len / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
    *output = (unsigned char*)malloc(output_len);
    if (!*output) {
        perror("Memory allocation failed for AES encryption");
        return -1;
    }

    for (size_t i = 0; i < input_len; i += AES_BLOCK_SIZE) {
        AES_ecb_encrypt(input + i, *output + i, &aes_key, AES_ENCRYPT);
    }

    return output_len;
}

int main() {
    // Load RSA private key from PEM file
    FILE* key_file = fopen("EXAM_2025_COLOCVIU/RSAPrivateKey.pem", "r");
    if (!key_file) {
        perror("Error opening private key file");
        return -1;
    }

    RSA* rsa = PEM_read_RSAPrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);

    if (!rsa) {
        perror("Error loading RSA private key");
        return -1;
    }

    // 1. Sign each SHA-256 digest of Accounts.txt and save them into AllSigns.sig
    unsigned char* accounts_file_data;
    size_t accounts_file_size = read_file("EXAM_2025_COLOCVIU/Accounts.txt", &accounts_file_data);
    if (accounts_file_size == 0) return -1;

    // Compute SHA-256 for each line in Accounts.txt
    FILE* signatures_file = fopen("EXAM_2025_COLOCVIU/AllSigns.sig", "wb");
    if (!signatures_file) {
        perror("Error opening AllSigns.sig for writing");
        free(accounts_file_data);
        return -1;
    }

    unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);

    size_t start = 0;
    for (size_t i = 0; i < accounts_file_size; ++i) {
        if (accounts_file_data[i] == '\n' || i == accounts_file_size - 1) {
            size_t line_len = i - start;
            SHA256_Update(&sha256_ctx, accounts_file_data + start, line_len);
            SHA256_Final(sha256_digest, &sha256_ctx);

            unsigned char* signature;
            unsigned int sig_len;
            if (sign_data(rsa, sha256_digest, SHA256_DIGEST_LENGTH, &signature, &sig_len) == -1) {
                fclose(signatures_file);
                free(accounts_file_data);
                return -1;
            }

            fwrite(signature, 1, sig_len, signatures_file);
            fwrite("\n", 1, 1, signatures_file); // New line after each signature

            free(signature);
            start = i + 1;
            SHA256_Init(&sha256_ctx); // Re-initialize SHA256 for next line
        }
    }
    fclose(signatures_file);

    // 2. Sign both Accounts.txt and AllSigns.sig files
    unsigned char accounts_file_digest[SHA256_DIGEST_LENGTH];
    SHA256(accounts_file_data, accounts_file_size, accounts_file_digest);


    unsigned char* all_signs_file_data;
    size_t all_signs_file_size = read_file("EXAM_2025_COLOCVIU/AllSigns.sig", &all_signs_file_data);

    FILE* sign1_file = fopen("EXAM_2025_COLOCVIU/Sign1.sig", "wb");
    FILE* sign2_file = fopen("EXAM_2025_COLOCVIU/Sign2.sig", "wb");

    unsigned char* signature;
    unsigned int sig_len;

    if (sign_data(rsa, accounts_file_digest, SHA256_DIGEST_LENGTH, &signature, &sig_len) == -1) {
        fclose(sign1_file);
        fclose(sign2_file);
        free(accounts_file_data);
        free(all_signs_file_data);
        return -1;
    }

    fwrite(signature, 1, sig_len, sign1_file);
    fclose(sign1_file);

    if (sign_data(rsa, all_signs_file_data, all_signs_file_size, &signature, &sig_len) == -1) {
        fclose(sign2_file);
        free(accounts_file_data);
        free(all_signs_file_data);
        return -1;
    }

    fwrite(signature, 1, sig_len, sign2_file);
    fclose(sign2_file);

    free(signature);

    // 3. Encrypt both Accounts.txt and AllSigns.sig using AES-ECB
    unsigned char key[AES_KEY_SIZE] = { 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12 };

    unsigned char* aes1_enc_data;
    size_t aes1_enc_len = encrypt_aes_ecb(key, accounts_file_data, accounts_file_size, &aes1_enc_data);
    FILE* aes1_file = fopen("EXAM_2025_COLOCVIU/aes1.enc", "wb");
    if (!aes1_file) {
        perror("Error opening aes1.enc for writing");
        free(aes1_enc_data);
        free(accounts_file_data);
        return -1;
    }
    fwrite(aes1_enc_data, 1, aes1_enc_len, aes1_file);
    fclose(aes1_file);
    free(aes1_enc_data);

    unsigned char* aes2_enc_data;
    size_t aes2_enc_len = encrypt_aes_ecb(key, all_signs_file_data, all_signs_file_size, &aes2_enc_data);
    FILE* aes2_file = fopen("EXAM_2025_COLOCVIU/aes2.enc", "wb");
    if (!aes2_file) {
        perror("Error opening aes2.enc for writing");
        free(aes2_enc_data);
        free(all_signs_file_data);
        return -1;
    }
    fwrite(aes2_enc_data, 1, aes2_enc_len, aes2_file);
    fclose(aes2_file);
    free(aes2_enc_data);

    free(accounts_file_data);
    free(all_signs_file_data);
    RSA_free(rsa);

    return 0;
}
