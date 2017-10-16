#include <stdio.h>
#include <strings.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

//AES-192
static signed char key[] = {7, 17, -82, -51, -48, 47, -38, 126, 80, 95, 52, -41, -105, -7, 71, -115, -33, -109, 94, 39, -58, 18, -97, 18};
static char* text        = "3000|sysadmin|08161b38c3650dba1e65a9d8a53e7128d6c8570f4622c032|OPENIAM_TOKEN";
static signed char encoded[]   = { 69, 22, -86, -75, 126, -66, 115, 30, -49, 62, -114, -20, -21, 99, -44, -20, 52, -45, 97, -39, 49, -41, -118, 48, -85, 
90, 78, 117, 114, -88, 78, -72, 122, -101, -33, -3, -110, -14, -72, 53, 79, 83, -11, -52, -75, 7, -104, -55, -100, -119, -45, -69, 81, -36, 71, 72,
-75, -48, 99, -46, 9, -121, 79, -113, 115, -102, 122, -68, -86, 86, -94, 60, 36, 30, 93, -94, -54, -3, 48, -44 };
unsigned char iv[EVP_MAX_IV_LENGTH];

int main(int argc, char** argv)
{
unsigned char iv[EVP_MAX_IV_LENGTH];
	printf("max iv size = %d", EVP_MAX_IV_LENGTH);
	printf("size of text %d", strlen(text));
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_EncryptInit_ex(&ctx, EVP_aes_192_cbc(), NULL, key, iv);

	int len = strlen(text);
	int c_len = len + AES_BLOCK_SIZE;
	signed char *ciphertext = malloc(c_len);

	  /* update ciphertext, c_len is filled with the length of ciphertext generated,
	    *len is the size of plaintext in bytes */
	EVP_EncryptUpdate(&ctx, ciphertext, &c_len, text, len);

	  /* update ciphertext with the final remaining bytes */
	int f_len;
	EVP_EncryptFinal_ex(&ctx, ciphertext+c_len, &f_len);
	printf("*");

	len = c_len + f_len;

	int i;
	printf ("length = %d", len);
	for (i =0; i < len; ++i) {
		if (encoded[i] == ciphertext[i]) {
			printf("(%02d)%d - ok\n", i, encoded[i]);
		} else {
			printf("(%02d) fail %d != %d", i, encoded[i], ciphertext[i]);
		}
	}
	int out_len = len;
	signed char *plaintext = malloc(out_len);

	EVP_DecryptInit_ex(&ctx, EVP_aes_192_cbc(), NULL, key, iv);
	EVP_DecryptUpdate(&ctx, plaintext, &out_len, encoded, len);
	char* last_buf=encoded+out_len;
	EVP_DecryptFinal(&ctx, last_buf, &len);
	len = len + out_len;
	EVP_CIPHER_CTX_cleanup(&ctx);

	printf ("length = %d", len);
	for (i =0; i < len; ++i) {
		if (text[i] == plaintext[i]) {
			printf("(%02d)%d - ok\n", i, text[i]);
		} else {
			printf("(%02d) fail %d != %d", i, text[i], plaintext[i]);
		}
	}

	return EXIT_SUCCESS;
}