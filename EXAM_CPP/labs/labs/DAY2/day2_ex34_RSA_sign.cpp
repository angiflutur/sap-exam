#define _CRT_SECURE_NO_DEPRECATE
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <malloc.h>
#include <stdio.h>
#include <openssl/applink.c>

int main()
{
	RSA* rsa_private;

	// usually the message digest SHA1 is re-computed against the restored message at the destination point 
	unsigned char SHA1[] = { 0x2b, 0xa2, 0x7c, 0xe4, 0xaf, 0xd6, 0xcb, 0x94, 0xa2, 0xcd, 0xc0, 0xda, 0x23, 0x72, 0x97, 0x75, 0xbf, 0x5c, 0x2f, 0xd8 };

	//read the key and load it in rsa_private
	FILE* fprivate = fopen("DAY2/RSAPrivateKey.pem", "r");
	rsa_private = PEM_read_RSAPrivateKey(fprivate, NULL, NULL, NULL);

	//get the key size
	int rsa_size = RSA_size(rsa_private);

	//mem allocation
	unsigned char* rsa_signature = (unsigned char*)malloc(rsa_size);

	//sign the message
	//size of message, message, pointer to sign, key, padding
	RSA_private_encrypt(sizeof(SHA1), SHA1, rsa_signature, rsa_private, RSA_PKCS1_PADDING); // the generated signature

	//savve the signature in signature.sig
	FILE* fsign = fopen("DAY2/signature.sig", "wb");
	fwrite(rsa_signature, rsa_size, 1, fsign); // save the signature into signature.sig

	RSA_free(rsa_private);
	fclose(fprivate);
	fclose(fsign);
	free(rsa_signature);

	return 0;
}