// OpenSSL Exam Cheatsheet in C++
// Includes: SHA256, AES-CBC/ECB, RSA keygen, sign/verify, encryption/decryption
// Compile with: g++ cheatsheet.cpp -o cheatsheet -lcrypto -lssl
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/applink.c> // REQUIRED for Windows

using namespace std;

// --- Utility Functions ---
vector<unsigned char> readFile(const string& filename) {
    ifstream file(filename, ios::binary);
    return vector<unsigned char>((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
}

void writeFile(const string& filename, const vector<unsigned char>& data) {
    ofstream file(filename, ios::binary);
    file.write((char*)data.data(), data.size());
}

void printHex(const vector<unsigned char>& data) {
    for (unsigned char byte : data)
        cout << hex << setw(2) << setfill('0') << (int)byte;
    cout << dec << endl;
}

// --- SHA256 Hash ---
vector<unsigned char> sha256(const vector<unsigned char>& data) {
    vector<unsigned char> digest(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), digest.data());
    return digest;
}

// --- AES-256-CBC Encrypt ---
vector<unsigned char> aesEncryptCBC(const vector<unsigned char>& plaintext, const vector<unsigned char>& key, const vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len, totalLen = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data());
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    totalLen += len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    totalLen += len;

    ciphertext.resize(totalLen);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

// --- AES-256-ECB Decrypt ---
vector<unsigned char> aesDecryptECB(const vector<unsigned char>& ciphertext, const vector<unsigned char>& key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    vector<unsigned char> plaintext(ciphertext.size());
    int len, totalLen = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key.data(), NULL);
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    totalLen += len;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    totalLen += len;

    plaintext.resize(totalLen);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

// --- RSA Key Generation ---
void generateRSAKey(const string& privFilename, const string& pubFilename) {
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, 1024, bn, NULL);

    FILE* priv = fopen(privFilename.c_str(), "wb");
    PEM_write_RSAPrivateKey(priv, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(priv);

    FILE* pub = fopen(pubFilename.c_str(), "wb");
    PEM_write_RSAPublicKey(pub, rsa);
    fclose(pub);

    RSA_free(rsa);
    BN_free(bn);
}

// --- RSA Sign (SHA256) ---
vector<unsigned char> rsaSign(const vector<unsigned char>& msg, const string& privKeyFile) {
    FILE* fp = fopen(privKeyFile.c_str(), "rb");
    RSA* rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    vector<unsigned char> sig(RSA_size(rsa));
    unsigned int sigLen;

    vector<unsigned char> digest = sha256(msg);
    RSA_sign(NID_sha256, digest.data(), digest.size(), sig.data(), &sigLen, rsa);

    sig.resize(sigLen);
    RSA_free(rsa);
    return sig;
}

// --- RSA Verify (SHA256) ---
bool rsaVerify(const vector<unsigned char>& msg, const vector<unsigned char>& sig, const string& pubKeyFile) {
    FILE* fp = fopen(pubKeyFile.c_str(), "rb");
    RSA* rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
    fclose(fp);

    vector<unsigned char> digest = sha256(msg);
    bool valid = RSA_verify(NID_sha256, digest.data(), digest.size(), sig.data(), sig.size(), rsa);

    RSA_free(rsa);
    return valid;
}

// --- Main Example (adapt as needed) ---
int main() {
    string name = "Angelica Example";
    writeFile("HELPER/name.txt", vector<unsigned char>(name.begin(), name.end()));

    // 1. Compute SHA256
    auto nameContent = readFile("HELPER/name.txt");
    auto hash = sha256(nameContent);
    cout << "SHA-256: "; printHex(hash);

    // 2. AES-CBC encrypt
    vector<unsigned char> iv = readFile("HELPER/iv.txt");
    vector<unsigned char> key = readFile("HELPER/aes.key");
    auto encrypted = aesEncryptCBC(nameContent, key, iv);
    writeFile("HELPER/enc_name.aes", encrypted);

    // 3. RSA Sign
    generateRSAKey("HELPER/private.pem", "HELPER/public.pem");
    auto signature = rsaSign(nameContent, "HELPER/private.pem");
    writeFile("HELPER/digital.sign", signature);

    return 0;
}
