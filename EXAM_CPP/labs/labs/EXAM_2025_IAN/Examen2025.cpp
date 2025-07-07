#define _CRT_SECURE_NO_WARNINGS
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/applink.c>

#define IV_SIZE 16
#define SALT "ISMsalt"

// IV specificat în cerință
unsigned char iv[IV_SIZE] = { 0xFF, 0xFF, 0xFF, 0xFF,
                              0xFF, 0xFF, 0xFF, 0xFF,
                              0x01, 0x02, 0x03, 0x04,
                              0x05, 0x06, 0x07, 0x08 };

// Funcție pentru citirea întregului fișier în memorie
size_t read_file(const char* filename, unsigned char** buffer) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        perror("Eroare deschidere fișier");
        return 0;
    }
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    *buffer = (unsigned char*)malloc(size);
    fread(*buffer, 1, size, f);
    fclose(f);
    return size;
}

// Funcție pentru afișarea unui buffer în hex
void print_hex(unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int main() {
    // 1. Decrypt signature.sig
    unsigned char* enc_sig = NULL;
    size_t sig_len = read_file("EXAM_2025_IAN/signature.sig", &enc_sig);

    FILE* key_file = fopen("EXAM_2025_IAN/RSAKey.pem", "r");
    if (!key_file) {
        perror("Eroare deschidere RSAKey.pem");
        return 1;
    }

    RSA* rsa = PEM_read_RSAPublicKey(key_file, NULL, NULL, NULL);
    fclose(key_file);

    if (!rsa) {
        fprintf(stderr, "Eroare citire cheie RSA\n");
        return 1;
    }

    unsigned char decrypted_hash[256]; // maxim pentru 2048-bit
    int dec_len = RSA_public_decrypt(sig_len, enc_sig, decrypted_hash, rsa, RSA_PKCS1_PADDING);
    if (dec_len <= 0) {
        fprintf(stderr, "Eroare decriptare semnătură\n");
        return 1;
    }

    printf("SHA-256 decriptat din semnătură:\n");
    print_hex(decrypted_hash, dec_len);

    // 2. Deschide wordlist.txt și parcurge fiecare linie
    FILE* wordlist = fopen("EXAM_2025_IAN/wordlist.txt", "r");
    if (!wordlist) {
        perror("Eroare deschidere wordlist.txt");
        return 1;
    }

    char line[256];
    int found = 0;
    int line_number = 0;
    char correct_word[256];
    unsigned char correct_hash[SHA256_DIGEST_LENGTH];

    while (fgets(line, sizeof(line), wordlist)) {
        line_number++;

        // Eliminăm newline
        line[strcspn(line, "\r\n")] = 0;

        // Concatenează cu SALT
        char salted_input[512];
        snprintf(salted_input, sizeof(salted_input), "%s%s", line, SALT);

        // Hash SHA-256
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char*)salted_input, strlen(salted_input), hash);

        // Compară cu hash-ul decriptat
        if (memcmp(hash, decrypted_hash, SHA256_DIGEST_LENGTH) == 0) {
            printf("Candidat găsit: %s (linie %d)\n", line, line_number);
            strcpy(correct_word, line);
            memcpy(correct_hash, hash, SHA256_DIGEST_LENGTH);
            found = 1;
            break;
        }
    }
    fclose(wordlist);
    free(enc_sig);
    RSA_free(rsa);

    if (!found) {
        printf("Nicio potrivire găsită.\n");
        return 0;
    }

    // 3. Encrypt parola folosind AES-256-CBC cu cheia = SHA256(parola+salt), IV dat
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Eroare creare context EVP\n");
        return 1;
    }

    unsigned char ciphertext[512];
    int len, ciphertext_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, correct_hash, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)correct_word, strlen(correct_word));
    ciphertext_len += len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    FILE* enc_out = fopen("EXAM_2025_IAN/word.enc", "wb");
    if (!enc_out) {
        perror("Eroare creare word.enc");
        return 1;
    }

    fwrite(ciphertext, 1, ciphertext_len, enc_out);
    fclose(enc_out);

    printf("Parola criptată și salvată în word.enc\n");
    return 0;
}
