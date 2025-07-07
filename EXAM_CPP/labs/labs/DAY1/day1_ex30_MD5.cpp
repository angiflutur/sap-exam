#include <stdio.h>
#include <malloc.h>
#include <openssl/md5.h>

#define MESSAGE_CHUNK 200  //200 bytes for reading the file in chunks

int main(int argc, char** argv)
{
	if (argc == 2) {
		//.\labs.exe ..\labs\DAY1\input.txt
		FILE* f = NULL;
		errno_t err;
		MD5_CTX ctx;

		unsigned char finalDigest[MD5_DIGEST_LENGTH];
		MD5_Init(&ctx); // initialization of the MD5_CTX structure

		unsigned char* fileBuffer = NULL;

		// the file is opened in binary mode
		err = fopen_s(&f, argv[1], "rb");
		if (err == 0) {
			fseek(f, 0, SEEK_END);
			int fileLen = ftell(f); //the file length
			fseek(f, 0, SEEK_SET);  //reset the file pointer to the beginning

			//memory allocation
			unsigned char* tmpBuffer_Chunk = (unsigned char*)malloc(MESSAGE_CHUNK);

			int read_length = MESSAGE_CHUNK;  //200 bytes
			while (read_length == MESSAGE_CHUNK) {
				//reading the file in chunks
				read_length = fread(tmpBuffer_Chunk, 1, MESSAGE_CHUNK, f);
				//update the hash with the new data
				MD5_Update(&ctx, tmpBuffer_Chunk, read_length);
			}

			//we store the final hash in finalDigest
			MD5_Final(finalDigest, &ctx); // saves the A, B, C, D blocks in the right order into the message digest buffer

			//printing the hash
			int count = 0;
			printf("\nMD5 = ");
			for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
				printf("%02x", finalDigest[i]);
			}

			printf("\n");

			fclose(f);
		}

	}
	else {
		printf("\n Usage Mode: ProgMainMD5.exe fSrc.txt \n\n");
		return 1;
	}

	return 0;
}