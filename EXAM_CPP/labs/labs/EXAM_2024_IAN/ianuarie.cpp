﻿#define _CRT_SECURE_NO_DEPRECATE
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/applink.c>
#include <stdio.h>
#include <malloc.h>
#include <memory.h>

void printArray(unsigned const char* const arr, unsigned const len, const char* const name)
{
	printf("\nThe content of the %s array is (hex): ", name);
	for (unsigned char i = 0; i < len; i++)
	{
		printf("%02x", arr[i]);
	}
}

int main()
{
	//1st req
	//1. Create a file named as name.txt to store your full name in 
	// text format. Compute and print out a SHA256 hash value into 
	// the running application console. 
	// The SHA-256 value will be displayed in hex format. 
	SHA256_CTX ctx;
	FILE* f = fopen("EXAM_2024_IAN/name.txt", "r");
	fseek(f, 0, SEEK_END);
	size_t len = ftell(f);
	fseek(f, 0, SEEK_SET);

	unsigned char* name = (unsigned char*)malloc(len);
	fread(name, len, 1, f);
	fclose(f);

	unsigned char digest[SHA256_DIGEST_LENGTH];
	SHA256_Init(&ctx);

	SHA256_Update(&ctx, name, len);

	SHA256_Final(digest, &ctx);

	printArray(digest, sizeof(digest), "sha256_of_my_name");

	//2nd req
	//Encrypt the file name.txt using AES-256 in CBC mode (2p):
	// - IV provided by the text file iv.txt and having the hex format to 
	// be imported into an internal buffer as binary format.
	// - AES - 256 bit key provided by the binary file named as aes.key.
	// The output encrypted file will be named as enc_name.aes.
	// No other data will be encrypted(e.g.IV,plaintext length and so forth) 
	// besides the content of name.txt.

	f = fopen("EXAM_2024_IAN/iv.txt", "r");
	unsigned char iv[AES_BLOCK_SIZE];
	unsigned char i = 0;
	unsigned int value;

	while (fscanf(f, " 0x%x,", &value) == 1 && i < AES_BLOCK_SIZE)
	{
		iv[i++] = (unsigned char)value;
	}

	fclose(f);

	f = fopen("EXAM_2024_IAN/aes.key", "rb");
	fseek(f, 0, SEEK_END);
	size_t key_len = ftell(f);
	fseek(f, 0, SEEK_SET);

	unsigned char* key = (unsigned char*)malloc(key_len);
	fread(key, key_len, 1, f);
	fclose(f);

	AES_KEY aes_key;

	AES_set_encrypt_key(key, key_len * 8, &aes_key);

	size_t partial_block = len % AES_BLOCK_SIZE ? 1 : 0;
	size_t ciphertext_blocks = len / AES_BLOCK_SIZE + partial_block;

	size_t padded_length = ciphertext_blocks * AES_BLOCK_SIZE;

	unsigned char* ciphertext = (unsigned char*)malloc(padded_length);

	printArray(iv, AES_BLOCK_SIZE, "iv");

	AES_cbc_encrypt(name, ciphertext, len, &aes_key, iv, AES_ENCRYPT);

	printArray(ciphertext, padded_length, "aes-256-cbc");

	f = fopen("EXAM_2024_IAN/enc_name.aes", "wb");
	fwrite(ciphertext, padded_length, 1, f);
	fclose(f);

	//3rd req
	//. To ensure the destination that no one is tampering with that value, 
	// digitally sign (computed for the above SHA - 256) the previous 
	// encrypted binary file with a RSA - 1024 bit private key 
	// generated by your application.Store the signature in another 
	// binary file named digital.sign. (2p)

	//Use the RSA - 1024 bit private key to sign the file name.txt.
	// Upload your binary signature file(digital.sign) together with the RSA 
	// - 1024 bit public key file.
	//To get the points, the digital signature must be validated 
	// during the assessment.

	RSA* rsa = NULL;
	rsa = RSA_generate_key(1024, USHRT_MAX, NULL, NULL);

	f = fopen("EXAM_2024_IAN/pub1.pem", "wb");
	PEM_write_RSAPublicKey(f, rsa);
	fclose(f);

	unsigned char computed_SHA[SHA256_DIGEST_LENGTH];

	SHA256_Init(&ctx);

	SHA256_Update(&ctx, ciphertext, padded_length);

	SHA256_Final(computed_SHA, &ctx);

	unsigned char* signature = (unsigned char*)malloc(RSA_size(rsa));
	size_t sig_size = 0;

	RSA_sign(NID_sha256, computed_SHA, SHA256_DIGEST_LENGTH, signature, &sig_size, rsa);
	//// în loc să refaci SHA256 pe ciphertext, semnează digest-ul calculat anterior:
	//RSA_sign(NID_sha256, digest, SHA256_DIGEST_LENGTH, signature, &sig_size, rsa);


	f = fopen("EXAM_2024_IAN/digital.sign", "wb");
	fwrite(signature, sig_size, 1, f);
	fclose(f);

	RSA_verify(NID_sha256, computed_SHA, SHA256_DIGEST_LENGTH, signature, sig_size, rsa) ? printf("\nVerification of the signature succeeded.") : printf("\nVerification of the signature failed.");
	//RSA_verify(NID_sha256, digest, SHA256_DIGEST_LENGTH, signature, sig_size, rsa) ?
	//	printf("\nVerification of the signature succeeded.") :
	//	printf("\nVerification of the signature failed.");


	RSA_free(rsa);
	free(ciphertext);
	free(key);
	free(name);

	return 0;
}