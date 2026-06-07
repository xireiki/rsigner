/*
 * aesgcm — AES-256-GCM encrypt/decrypt helper
 * Reads plain/cipher from stdin, writes result to stdout.
 *
 * Usage:
 *   encrypt: aesgcm e <key:32> <iv:12>   < tagfile   < plaintext  → ciphertext
 *   decrypt: aesgcm d <key:32> <iv:12> tagfile       < ciphertext → plaintext
 *
 * Tag is read from/written to a separate file (hex).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define TAG_LEN 16

static void die_openssl(const char *label) {
	unsigned long e = ERR_get_error();
	if (e)
		fprintf(stderr, "aesgcm: %s: %s\n", label, ERR_error_string(e, NULL));
	else
		fprintf(stderr, "aesgcm: %s: unknown error\n", label);
	exit(1);
}

static void hex2bin(const char *hex, unsigned char *out, int len) {
	for (int i = 0; i < len; i++) {
		unsigned int b;
		sscanf(hex + i * 2, "%02x", &b);
		out[i] = (unsigned char)b;
	}
}

static void bin2hex(const unsigned char *bin, int len, char *out) {
	for (int i = 0; i < len; i++)
		sprintf(out + i * 2, "%02x", bin[i]);
}

int main(int argc, char **argv) {
	if (argc < 4) {
		fprintf(stderr, "Usage: aesgcm e|d <hexkey> <hexiv> [tagfile]\n");
		return 1;
	}

	int encrypt = (argv[1][0] == 'e');
	unsigned char key[32], iv[12];
	hex2bin(argv[2], key, 32);
	hex2bin(argv[3], iv, 12);
	unsigned char tag[TAG_LEN];
	const char *tagfile = argv[4];

	if (!encrypt) {
		/* read tag file */
		FILE *fp = fopen(tagfile, "r");
		if (!fp) { perror("open tagfile"); return 1; }
		char hex[33];
		if (!fgets(hex, sizeof(hex), fp)) { fprintf(stderr, "read tagfile\n"); return 1; }
		fclose(fp);
		hex2bin(hex, tag, TAG_LEN);
	}

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) die_openssl("EVP_CIPHER_CTX_new");

	const EVP_CIPHER *cipher = EVP_aes_256_gcm();

	if (encrypt) {
		if (!EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv))
			die_openssl("EVP_EncryptInit_ex");

		/* read stdin */
		unsigned char buf[65536];
		int n;
		unsigned char out[65536 + 16];
		int outlen, tmplen;

		while ((n = fread(buf, 1, sizeof(buf), stdin)) > 0) {
			if (!EVP_EncryptUpdate(ctx, out, &outlen, buf, n))
				die_openssl("EVP_EncryptUpdate");
			fwrite(out, 1, outlen, stdout);
		}
		if (!EVP_EncryptFinal_ex(ctx, out, &tmplen))
			die_openssl("EVP_EncryptFinal_ex");
		fwrite(out, 1, tmplen, stdout);

		if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag))
			die_openssl("EVP_CTRL_GCM_GET_TAG");

		/* write tag file */
		FILE *fp = fopen(tagfile, "w");
		if (!fp) { perror("write tagfile"); return 1; }
		char hex[33];
		bin2hex(tag, TAG_LEN, hex);
		hex[32] = '\0';
		fprintf(fp, "%s\n", hex);
		fclose(fp);
	} else {
		if (!EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv))
			die_openssl("EVP_DecryptInit_ex");

		unsigned char buf[65536];
		int n;
		unsigned char out[65536 + 16];
		int outlen, tmplen;

		while ((n = fread(buf, 1, sizeof(buf), stdin)) > 0) {
			if (!EVP_DecryptUpdate(ctx, out, &outlen, buf, n))
				die_openssl("EVP_DecryptUpdate");
			fwrite(out, 1, outlen, stdout);
		}

		if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag))
			die_openssl("EVP_CTRL_GCM_SET_TAG");

		if (!EVP_DecryptFinal_ex(ctx, out, &tmplen)) {
			die_openssl("EVP_DecryptFinal_ex (GCM auth failed)");
		}
		fwrite(out, 1, tmplen, stdout);
	}

	EVP_CIPHER_CTX_free(ctx);
	fflush(stdout);
	return 0;
}
