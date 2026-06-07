/*
 * rsigner — RSA message recovery sign + AES-256-GCM encrypt/decrypt
 *
 * Protocol: see README.md
 * Build:    gcc -O2 -s -o rsigner rsigner.c -lcrypto
 * Strip:    strip rsigner
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <stdarg.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#define SEED_LEN    32
#define HASH_LEN    32
#define IV_LEN      12
#define TAG_LEN     16
#define MESSAGE_LEN (SEED_LEN + HASH_LEN + IV_LEN + TAG_LEN)

/* ─── error helpers ─────────────────────────────────────────────── */

static void die_openssl(const char *label) {
	unsigned long e = ERR_get_error();
	if (e)
		fprintf(stderr, "Error: %s: %s\n", label, ERR_error_string(e, NULL));
	else
		fprintf(stderr, "Error: %s: unknown error\n", label);
	exit(1);
}

__attribute__((noreturn))
static void die(const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(1);
}

/* ─── key generation ──────────────────────────────────────────────── */

static EVP_PKEY *generate_key(int bits) {
	if (bits < 2048)
		die("RSA key must be at least 2048 bits (requested %d)", bits);

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (!ctx) die_openssl("EVP_PKEY_CTX_new_id");

	if (EVP_PKEY_keygen_init(ctx) <= 0)
		{ EVP_PKEY_CTX_free(ctx); die_openssl("keygen_init"); }
	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
		{ EVP_PKEY_CTX_free(ctx); die_openssl("set_rsa_keygen_bits"); }

	EVP_PKEY *pkey = NULL;
	if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
		{ EVP_PKEY_CTX_free(ctx); die_openssl("keygen"); }
	EVP_PKEY_CTX_free(ctx);
	return pkey;
}

/* ─── PEM I/O ────────────────────────────────────────────────────── */

static EVP_PKEY *read_private_key(const char *path) {
	FILE *fp = fopen(path, "rb");
	if (!fp) die("open %s: %s", path, strerror(errno));
	EVP_PKEY *key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	if (!key) die_openssl("PEM_read_PrivateKey");
	return key;
}

static EVP_PKEY *read_public_key(const char *path) {
	FILE *fp = fopen(path, "rb");
	if (!fp) die("open %s: %s", path, strerror(errno));
	EVP_PKEY *key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
	fclose(fp);
	if (!key) die_openssl("PEM_read_PUBKEY");
	return key;
}

static void write_private_key(const char *path, EVP_PKEY *key) {
	FILE *fp = fopen(path, "wb");
	if (!fp) die("create %s: %s", path, strerror(errno));
	if (!PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL))
		{ fclose(fp); die_openssl("PEM_write_PrivateKey"); }
	fclose(fp);
}

static void write_public_key(const char *path, EVP_PKEY *key) {
	FILE *fp = fopen(path, "wb");
	if (!fp) die("create %s: %s", path, strerror(errno));
	if (!PEM_write_PUBKEY(fp, key))
		{ fclose(fp); die_openssl("PEM_write_PUBKEY"); }
	fclose(fp);
}

/* ─── crypto primitives ──────────────────────────────────────────── */

static void sha256_hash(const unsigned char *data, size_t len,
			unsigned char out[32]) {
	unsigned int hlen = 32;
	if (!EVP_Digest(data, len, out, &hlen, EVP_sha256(), NULL))
		die_openssl("EVP_Digest");
}

static void derive_key(const unsigned char seed[32],
			const unsigned char hash[32],
			unsigned char out[32]) {
	unsigned int klen = 32;
	unsigned char *r = HMAC(EVP_sha256(), seed, SEED_LEN,
				hash, HASH_LEN, out, &klen);
	if (!r) die_openssl("HMAC");
}

static void random_bytes(unsigned char *buf, int n) {
	if (!RAND_bytes(buf, n))
		die_openssl("RAND_bytes");
}

/* ---- AES-256-GCM -------------------------------------------------- */

static void aes_gcm_encrypt(const unsigned char *pt, size_t pt_len,
			    const unsigned char key[32],
			    const unsigned char iv[12],
			    unsigned char **ct, size_t *ct_len,
			    unsigned char tag[16])
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) die_openssl("EVP_CIPHER_CTX_new");

	if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		{ EVP_CIPHER_CTX_free(ctx); die_openssl("EVP_EncryptInit_ex"); }
	if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
		{ EVP_CIPHER_CTX_free(ctx); die_openssl("EVP_EncryptInit_ex (key+iv)"); }

	*ct = malloc(pt_len + 16);
	if (!*ct) { EVP_CIPHER_CTX_free(ctx); die("malloc failed"); }

	int outlen = 0, tmplen = 0;
	if (!EVP_EncryptUpdate(ctx, *ct, &outlen, pt, (int)pt_len))
		{ EVP_CIPHER_CTX_free(ctx); die_openssl("EVP_EncryptUpdate"); }
	if (!EVP_EncryptFinal_ex(ctx, *ct + outlen, &tmplen))
		{ EVP_CIPHER_CTX_free(ctx); die_openssl("EVP_EncryptFinal_ex"); }
	*ct_len = (size_t)(outlen + tmplen);

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag))
		{ EVP_CIPHER_CTX_free(ctx); die_openssl("EVP_CTRL_GCM_GET_TAG"); }
	EVP_CIPHER_CTX_free(ctx);
}

static unsigned char *aes_gcm_decrypt(const unsigned char *ct, size_t ct_len,
				      const unsigned char key[32],
				      const unsigned char iv[12],
				      const unsigned char tag[16],
				      size_t *pt_len)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) die_openssl("EVP_CIPHER_CTX_new");

	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		{ EVP_CIPHER_CTX_free(ctx); die_openssl("EVP_DecryptInit_ex"); }
	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
		{ EVP_CIPHER_CTX_free(ctx); die_openssl("EVP_DecryptInit_ex (key+iv)"); }

	unsigned char *pt = malloc(ct_len + 16);
	if (!pt) { EVP_CIPHER_CTX_free(ctx); die("malloc failed"); }

	int outlen = 0, tmplen = 0;
	if (!EVP_DecryptUpdate(ctx, pt, &outlen, ct, (int)ct_len))
		{ EVP_CIPHER_CTX_free(ctx); die_openssl("EVP_DecryptUpdate"); }

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag))
		{ EVP_CIPHER_CTX_free(ctx); die_openssl("EVP_CTRL_GCM_SET_TAG"); }

	if (!EVP_DecryptFinal_ex(ctx, pt + outlen, &tmplen)) {
		EVP_CIPHER_CTX_free(ctx);
		free(pt);
		die("decrypt failed: GCM authentication failed");
	}
	*pt_len = (size_t)(outlen + tmplen);
	EVP_CIPHER_CTX_free(ctx);
	return pt;
}

/* ---- RSA message recovery (raw PKCS#1 v1.5) ----------------------- */

static unsigned char *rsa_sign_raw(EVP_PKEY *key,
				   const unsigned char *msg, size_t msg_len,
				   size_t *sig_len)
{
	RSA *rsa = EVP_PKEY_get1_RSA(key);
	if (!rsa) die_openssl("EVP_PKEY_get1_RSA");

	int k = RSA_size(rsa);
	unsigned char *sig = malloc((size_t)k);
	if (!sig) { RSA_free(rsa); die("malloc failed"); }

	int n = RSA_private_encrypt((int)msg_len, msg, sig, rsa, RSA_PKCS1_PADDING);
	if (n < 0) { RSA_free(rsa); free(sig); die_openssl("RSA_private_encrypt"); }
	*sig_len = (size_t)n;
	RSA_free(rsa);
	return sig;
}

static unsigned char *rsa_verify_recover(EVP_PKEY *key,
					 const unsigned char *sig,
					 size_t sig_len, size_t *msg_len)
{
	RSA *rsa = EVP_PKEY_get1_RSA(key);
	if (!rsa) die_openssl("EVP_PKEY_get1_RSA");

	int k = RSA_size(rsa);
	if ((int)sig_len != k) {
		RSA_free(rsa);
		die("signature length does not match modulus: got %zu, want %d",
		    sig_len, k);
	}

	unsigned char *msg = malloc((size_t)k);
	if (!msg) { RSA_free(rsa); die("malloc failed"); }

	int n = RSA_public_decrypt((int)sig_len, sig, msg, rsa, RSA_PKCS1_PADDING);
	if (n < 0) { RSA_free(rsa); free(msg); die_openssl("RSA_public_decrypt"); }
	*msg_len = (size_t)n;
	RSA_free(rsa);
	return msg;
}

/* ─── high-level operations ──────────────────────────────────────── */

static void encrypt_core(const unsigned char *plaintext, size_t pt_len,
			 EVP_PKEY *priv,
			 unsigned char **sig, size_t *sig_len,
			 unsigned char **ciphertext, size_t *ct_len)
{
	unsigned char h[HASH_LEN];
	sha256_hash(plaintext, pt_len, h);

	unsigned char seed[SEED_LEN];
	random_bytes(seed, SEED_LEN);

	unsigned char k[32];
	derive_key(seed, h, k);

	unsigned char iv[IV_LEN];
	random_bytes(iv, IV_LEN);

	unsigned char tag[TAG_LEN];
	aes_gcm_encrypt(plaintext, pt_len, k, iv, ciphertext, ct_len, tag);

	/* pack M = S || H || IV || Tag */
	unsigned char msg[MESSAGE_LEN];
	memcpy(msg, seed, SEED_LEN);
	memcpy(msg + SEED_LEN, h, HASH_LEN);
	memcpy(msg + SEED_LEN + HASH_LEN, iv, IV_LEN);
	memcpy(msg + SEED_LEN + HASH_LEN + IV_LEN, tag, TAG_LEN);

	*sig = rsa_sign_raw(priv, msg, MESSAGE_LEN, sig_len);
}

static unsigned char *decrypt_core(const unsigned char *sig, size_t sig_len,
				   const unsigned char *ciphertext,
				   size_t ct_len, EVP_PKEY *pub,
				   size_t *pt_len)
{
	size_t msg_len;
	unsigned char *msg = rsa_verify_recover(pub, sig, sig_len, &msg_len);
	if (msg_len < MESSAGE_LEN) {
		free(msg);
		die("recovered message too short: need %d, got %zu",
		    MESSAGE_LEN, msg_len);
	}

	unsigned char *seed   = msg;
	unsigned char *h      = msg + SEED_LEN;
	unsigned char *iv     = msg + SEED_LEN + HASH_LEN;
	unsigned char *tag    = msg + SEED_LEN + HASH_LEN + IV_LEN;

	unsigned char k[32];
	derive_key(seed, h, k);

	unsigned char *plaintext = aes_gcm_decrypt(ciphertext, ct_len,
						   k, iv, tag, pt_len);
	free(msg);

	/* verify hash */
	unsigned char computed_h[HASH_LEN];
	sha256_hash(plaintext, *pt_len, computed_h);
	if (memcmp(computed_h, h, HASH_LEN) != 0) {
		free(plaintext);
		die("hash mismatch: decrypted content does not match original");
	}
	return plaintext;
}

/* ─── file I/O ────────────────────────────────────────────────────── */

static unsigned char *read_file(const char *path, size_t *len) {
	if (strcmp(path, "-") == 0) {
		/* read stdin */
		size_t cap = 8192, n = 0;
		unsigned char *buf = malloc(cap);
		if (!buf) die("malloc failed");
		int c;
		while ((c = getchar()) != EOF) {
			if (n >= cap) {
				cap *= 2;
				buf = realloc(buf, cap);
				if (!buf) die("realloc failed");
			}
			buf[n++] = (unsigned char)c;
		}
		*len = n;
		return buf;
	}

	FILE *fp = fopen(path, "rb");
	if (!fp) die("open %s: %s", path, strerror(errno));
	fseek(fp, 0, SEEK_END);
	*len = (size_t)ftell(fp);
	fseek(fp, 0, SEEK_SET);

	unsigned char *buf = malloc(*len + 1);
	if (!buf) { fclose(fp); die("malloc failed"); }
	if (fread(buf, 1, *len, fp) != *len) {
		fclose(fp);
		free(buf);
		die("read %s: short read", path);
	}
	fclose(fp);
	return buf;
}

static void write_file(const char *path, const unsigned char *data,
		       size_t len)
{
	if (strcmp(path, "-") == 0) {
		fwrite(data, 1, len, stdout);
		fflush(stdout);
		return;
	}
	FILE *fp = fopen(path, "wb");
	if (!fp) die("create %s: %s", path, strerror(errno));
	if (fwrite(data, 1, len, fp) != len) {
		fclose(fp);
		die("write %s: short write", path);
	}
	fclose(fp);
}

/* ─── subcommand handlers ────────────────────────────────────────── */

static int genkey_main(int argc, char **argv) {
	int bits = 2048;
	const char *priv_out = "private.pem";
	const char *pub_out  = "public.pem";

	optind = 1;
	int c;
	while ((c = getopt(argc, argv, "g:k:K:h")) != -1) {
		switch (c) {
		case 'g': bits = atoi(optarg); break;
		case 'k': priv_out = optarg; break;
		case 'K': pub_out  = optarg; break;
		case 'h':
			fprintf(stderr, "Usage: rsigner genkey [-g bits] [-k priv] [-K pub]\n");
			return 0;
		default:
			fprintf(stderr, "Usage: rsigner genkey [-g bits] [-k priv] [-K pub]\n");
			return 1;
		}
	}

	EVP_PKEY *key = generate_key(bits);
	write_private_key(priv_out, key);
	write_public_key(pub_out, key);
	EVP_PKEY_free(key);
	fprintf(stderr, "Done.\n");
	return 0;
}

static int encrypt_main(int argc, char **argv) {
	const char *priv_key = NULL;
	const char *input    = "-";
	const char *sig_out  = NULL;
	const char *ciph_out = NULL;
	int sig_own = 0, ciph_own = 0;

	optind = 1;
	int c;
	while ((c = getopt(argc, argv, "k:i:s:o:h")) != -1) {
		switch (c) {
		case 'k': priv_key = optarg; break;
		case 'i': input    = optarg; break;
		case 's': sig_out  = optarg; break;
		case 'o': ciph_out = optarg; break;
		case 'h':
			fprintf(stderr, "Usage: rsigner encrypt -k privkey [-i input] [-s sig] [-o out]\n");
			return 0;
		default:
			fprintf(stderr, "Usage: rsigner encrypt -k privkey [-i input] [-s sig] [-o out]\n");
			return 1;
		}
	}
	if (!priv_key) die("encrypt requires -k/--private-key");

	if (!sig_out) {
		if (strcmp(input, "-") == 0) {
			sig_out = "sign.sig";
		} else {
			size_t n = strlen(input);
			char *s = malloc(n + 5);
			if (!s) die("malloc failed");
			memcpy(s, input, n);
			memcpy(s + n, ".sig", 5);
			sig_out = s;
			sig_own = 1;
		}
	}
	if (!ciph_out) {
		if (strcmp(input, "-") == 0) {
			ciph_out = "cipher.rsn";
		} else {
			size_t n = strlen(input);
			char *s = malloc(n + 5);
			if (!s) die("malloc failed");
			memcpy(s, input, n);
			memcpy(s + n, ".rsn", 5);
			ciph_out = s;
			ciph_own = 1;
		}
	}

	EVP_PKEY *key = read_private_key(priv_key);

	size_t pt_len;
	unsigned char *pt = read_file(input, &pt_len);

	unsigned char *sig, *ct;
	size_t sig_len, ct_len;
	encrypt_core(pt, pt_len, key, &sig, &sig_len, &ct, &ct_len);

	write_file(sig_out, sig, sig_len);
	write_file(ciph_out, ct, ct_len);

	free(pt); free(sig); free(ct);
	EVP_PKEY_free(key);

	if (sig_own) free((void *)sig_out);
	if (ciph_own) free((void *)ciph_out);

	fprintf(stderr, "Done.\n");
	return 0;
}

static int decrypt_main(int argc, char **argv) {
	const char *pub_key  = NULL;
	const char *sig_in   = NULL;
	const char *ciph_in  = NULL;
	const char *pt_out   = NULL;
	int pt_own = 0;

	optind = 1;
	int c;
	while ((c = getopt(argc, argv, "K:s:i:o:h")) != -1) {
		switch (c) {
		case 'K': pub_key = optarg; break;
		case 's': sig_in  = optarg; break;
		case 'i': ciph_in = optarg; break;
		case 'o': pt_out  = optarg; break;
		case 'h':
			fprintf(stderr, "Usage: rsigner decrypt -K pubkey -s sig -i input [-o out]\n");
			return 0;
		default:
			fprintf(stderr, "Usage: rsigner decrypt -K pubkey -s sig -i input [-o out]\n");
			return 1;
		}
	}
	if (!pub_key) die("decrypt requires -K/--public-key");
	if (!sig_in)  die("decrypt requires -s/--sign");
	if (!ciph_in) die("decrypt requires -i/--input");

	if (!pt_out) {
		if (strcmp(ciph_in, "-") == 0) {
			pt_out = "output.dec";
		} else {
			size_t n = strlen(ciph_in);
			if (n > 4 && strcmp(ciph_in + n - 4, ".rsn") == 0) {
				char *s = malloc(n - 3);
				if (!s) die("malloc failed");
				memcpy(s, ciph_in, n - 4);
				s[n - 4] = '\0';
				pt_out = s;
				pt_own = 1;
			} else {
				pt_out = "output.dec";
			}
		}
	}

	EVP_PKEY *key = read_public_key(pub_key);

	size_t sig_len, ct_len;
	unsigned char *sig = read_file(sig_in, &sig_len);
	unsigned char *ct  = read_file(ciph_in, &ct_len);

	size_t pt_len;
	unsigned char *pt = decrypt_core(sig, sig_len, ct, ct_len, key, &pt_len);

	write_file(pt_out, pt, pt_len);

	free(pt); free(sig); free(ct);
	EVP_PKEY_free(key);

	if (pt_own) free((void *)pt_out);

	fprintf(stderr, "Done.\n");
	return 0;
}

/* ─── main ───────────────────────────────────────────────────────── */

static void usage(void) {
	fprintf(stderr,
		"Usage: rsigner <command> [flags]\n\n"
		"Commands:\n"
		"  genkey    Generate RSA key pair\n"
		"  encrypt   Encrypt file\n"
		"  decrypt   Decrypt file\n"
		"Run 'rsigner <command> -h' for command-specific help.\n");
}

int main(int argc, char **argv) {
	if (argc < 2) { usage(); return 1; }

	if (strcmp(argv[1], "genkey") == 0)
		return genkey_main(argc - 1, argv + 1);
	if (strcmp(argv[1], "encrypt") == 0)
		return encrypt_main(argc - 1, argv + 1);
	if (strcmp(argv[1], "decrypt") == 0)
		return decrypt_main(argc - 1, argv + 1);
	if (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "-h") == 0 ||
	    strcmp(argv[1], "--help") == 0) {
		usage();
		return 0;
	}

	fprintf(stderr, "Unknown command: %s\nRun 'rsigner help' for usage.\n",
		argv[1]);
	return 1;
}
