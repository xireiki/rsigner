#!/usr/bin/env python3
"""
rsigner — RSA message recovery sign + AES-256-GCM encrypt/decrypt
Pure Python implementation using ctypes → libcrypto (OpenSSL 3.x)
"""
import argparse
import ctypes
import os
import sys
from ctypes import c_int, c_char_p, c_void_p, c_uint, c_size_t, \
    POINTER, byref, create_string_buffer

# ─── libcrypto bindings ─────────────────────────────────────────────────

lib = ctypes.CDLL("libcrypto.so.3")
ERR_get_error = lib.ERR_get_error
ERR_get_error.restype = c_ulong = ctypes.c_ulong
lib.ERR_error_string.restype = c_char_p
lib.ERR_error_string.argtypes = [c_ulong, c_char_p]

def openssl_err(label=""):
    e = ERR_get_error()
    msg = ""
    if e:
        msg = lib.ERR_error_string(e, None).decode()
    return f"OpenSSL error{f' ({label})' if label else ''}: {msg or 'unknown'}"

def check(ret, label=""):
    if ret != 1:
        raise RuntimeError(openssl_err(label))

# ─── EVP_PKEY ──────────────────────────────────────────────────────────

lib.EVP_PKEY_CTX_new_id.restype = c_void_p
lib.EVP_PKEY_CTX_new_id.argtypes = [c_int, c_void_p]

lib.EVP_PKEY_CTX_free.argtypes = [c_void_p]
lib.EVP_PKEY_keygen_init.argtypes = [c_void_p]
lib.EVP_PKEY_keygen_init.restype = c_int
lib.EVP_PKEY_CTX_set_rsa_keygen_bits.argtypes = [c_void_p, c_int]
lib.EVP_PKEY_CTX_set_rsa_keygen_bits.restype = c_int

lib.EVP_PKEY_keygen.argtypes = [c_void_p, POINTER(c_void_p)]
lib.EVP_PKEY_keygen.restype = c_int

lib.EVP_PKEY_free.argtypes = [c_void_p]
lib.EVP_PKEY_up_ref.argtypes = [c_void_p]
lib.EVP_PKEY_up_ref.restype = c_int

EVP_PKEY_RSA = 6  # from <openssl/evp.h>

# ─── RSA legacy (message recovery) ─────────────────────────────────────

lib.EVP_PKEY_get1_RSA.restype = c_void_p
lib.EVP_PKEY_get1_RSA.argtypes = [c_void_p]

lib.RSA_free.argtypes = [c_void_p]
lib.RSA_size.restype = c_int
lib.RSA_size.argtypes = [c_void_p]

lib.RSA_private_encrypt.restype = c_int
lib.RSA_private_encrypt.argtypes = [c_int, c_char_p, c_char_p, c_void_p, c_int]
lib.RSA_public_decrypt.restype = c_int
lib.RSA_public_decrypt.argtypes = [c_int, c_char_p, c_char_p, c_void_p, c_int]
RSA_PKCS1_PADDING = 1

# ─── PEM I/O ───────────────────────────────────────────────────────────

lib.PEM_read_bio_PrivateKey.restype = c_void_p
lib.PEM_read_bio_PrivateKey.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p]
lib.PEM_read_bio_PUBKEY.restype = c_void_p
lib.PEM_read_bio_PUBKEY.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p]
lib.PEM_write_bio_PrivateKey.restype = c_int
lib.PEM_write_bio_PrivateKey.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p, c_int, c_void_p, c_void_p]
lib.PEM_write_bio_PUBKEY.restype = c_int
lib.PEM_write_bio_PUBKEY.argtypes = [c_void_p, c_void_p]

# BIO
lib.BIO_new_mem_buf.restype = c_void_p
lib.BIO_new_mem_buf.argtypes = [c_void_p, c_int]
lib.BIO_new.restype = c_void_p
lib.BIO_new.argtypes = [c_void_p]
lib.BIO_s_mem.restype = c_void_p
lib.BIO_s_mem.argtypes = []
lib.BIO_free.argtypes = [c_void_p]
lib.BIO_ctrl.restype = c_long = ctypes.c_long
lib.BIO_ctrl.argtypes = [c_void_p, c_int, c_long, c_void_p]
BIO_CTRL_INFO = 3

# ─── AES-256-GCM ───────────────────────────────────────────────────────

lib.EVP_CIPHER_CTX_new.restype = c_void_p
lib.EVP_CIPHER_CTX_new.argtypes = []
lib.EVP_CIPHER_CTX_free.argtypes = [c_void_p]

lib.EVP_aes_256_gcm.restype = c_void_p
lib.EVP_aes_256_gcm.argtypes = []

lib.EVP_EncryptInit_ex.restype = c_int
lib.EVP_EncryptInit_ex.argtypes = [c_void_p, c_void_p, c_void_p, c_char_p, c_char_p]
lib.EVP_EncryptUpdate.restype = c_int
lib.EVP_EncryptUpdate.argtypes = [c_void_p, c_char_p, POINTER(c_int), c_char_p, c_int]
lib.EVP_EncryptFinal_ex.restype = c_int
lib.EVP_EncryptFinal_ex.argtypes = [c_void_p, c_char_p, POINTER(c_int)]

lib.EVP_DecryptInit_ex.argtypes = lib.EVP_EncryptInit_ex.argtypes
lib.EVP_DecryptInit_ex.restype = c_int
lib.EVP_DecryptUpdate.argtypes = lib.EVP_EncryptUpdate.argtypes
lib.EVP_DecryptUpdate.restype = c_int
lib.EVP_DecryptFinal_ex.argtypes = [c_void_p, c_char_p, POINTER(c_int)]
lib.EVP_DecryptFinal_ex.restype = c_int

lib.EVP_CIPHER_CTX_ctrl.restype = c_int
lib.EVP_CIPHER_CTX_ctrl.argtypes = [c_void_p, c_int, c_int, c_void_p]
EVP_CTRL_GCM_GET_TAG = 0x10
EVP_CTRL_GCM_SET_TAG = 0x11

# ─── HASH / HMAC / RAND ────────────────────────────────────────────────

lib.EVP_Digest.restype = c_int
lib.EVP_Digest.argtypes = [c_char_p, c_size_t, c_char_p, POINTER(c_uint),
                           c_void_p, c_void_p]
lib.EVP_sha256.restype = c_void_p
lib.EVP_sha256.argtypes = []

lib.HMAC.restype = c_char_p
lib.HMAC.argtypes = [c_void_p, c_char_p, c_int, c_char_p, c_size_t,
                     c_char_p, POINTER(c_uint)]

lib.RAND_bytes.restype = c_int
lib.RAND_bytes.argtypes = [c_char_p, c_int]

# ─── constants ─────────────────────────────────────────────────────────

SEED_LEN = 32
HASH_LEN = 32
IV_LEN = 12
TAG_LEN = 16
MESSAGE_LEN = SEED_LEN + HASH_LEN + IV_LEN + TAG_LEN

# ─── helpers ───────────────────────────────────────────────────────────

def sha256(data: bytes) -> bytes:
    md = create_string_buffer(HASH_LEN)
    mdlen = c_uint(HASH_LEN)
    check(lib.EVP_Digest(data, len(data), md, byref(mdlen),
                         lib.EVP_sha256(), None), "EVP_Digest")
    return md.raw[:HASH_LEN]

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    out = create_string_buffer(HASH_LEN)
    outlen = c_uint(HASH_LEN)
    r = lib.HMAC(lib.EVP_sha256(), key, len(key), data, len(data),
                 out, byref(outlen))
    if not r:
        raise RuntimeError(openssl_err("HMAC"))
    return out.raw[:HASH_LEN]

def random_bytes(n: int) -> bytes:
    buf = create_string_buffer(n)
    check(lib.RAND_bytes(buf, n), "RAND_bytes")
    return buf.raw[:n]

# ─── RSA message recovery ──────────────────────────────────────────────

def _rsa_from_pkey(pkey):
    rsa = lib.EVP_PKEY_get1_RSA(pkey)
    if not rsa:
        raise RuntimeError(openssl_err("EVP_PKEY_get1_RSA"))
    return rsa

def rsa_sign_raw(pkey, msg: bytes) -> bytes:
    rsa = _rsa_from_pkey(pkey)
    try:
        k = lib.RSA_size(rsa)
        sig = create_string_buffer(k)
        n = lib.RSA_private_encrypt(len(msg), msg, sig, rsa, RSA_PKCS1_PADDING)
        if n < 0:
            raise RuntimeError(openssl_err("RSA_private_encrypt"))
        return sig.raw[:n]
    finally:
        lib.RSA_free(rsa)

def rsa_verify_recover(pkey, sig: bytes) -> bytes:
    rsa = _rsa_from_pkey(pkey)
    try:
        k = lib.RSA_size(rsa)
        if len(sig) != k:
            raise ValueError(f"signature length mismatch: got {len(sig)}, want {k}")
        out = create_string_buffer(k)
        n = lib.RSA_public_decrypt(len(sig), sig, out, rsa, RSA_PKCS1_PADDING)
        if n < 0:
            raise RuntimeError(openssl_err("RSA_public_decrypt"))
        return out.raw[:n]
    finally:
        lib.RSA_free(rsa)

# ─── PEM I/O ───────────────────────────────────────────────────────────

def _bio_read(bio) -> bytes:
    buf = c_char_p()
    n = lib.BIO_ctrl(bio, BIO_CTRL_INFO, 0, byref(buf))
    if n <= 0:
        raise RuntimeError(openssl_err("BIO_ctrl"))
    return ctypes.string_at(buf, n)

def _bio_from_bytes(data: bytes):
    bio = lib.BIO_new_mem_buf(data, len(data))
    if not bio:
        raise RuntimeError(openssl_err("BIO_new_mem_buf"))
    return bio

def read_private_key(path: str):
    with open(path, "rb") as f:
        data = f.read()
    bio = _bio_from_bytes(data)
    try:
        pkey = lib.PEM_read_bio_PrivateKey(bio, None, None, None)
        if not pkey:
            raise RuntimeError(openssl_err("PEM_read_bio_PrivateKey"))
        return pkey
    finally:
        lib.BIO_free(bio)

def read_public_key(path: str):
    with open(path, "rb") as f:
        data = f.read()
    bio = _bio_from_bytes(data)
    try:
        pkey = lib.PEM_read_bio_PUBKEY(bio, None, None, None)
        if not pkey:
            raise RuntimeError(openssl_err("PEM_read_bio_PUBKEY"))
        return pkey
    finally:
        lib.BIO_free(bio)

def write_private_key(path: str, pkey):
    bio = lib.BIO_new(lib.BIO_s_mem())
    if not bio:
        raise RuntimeError(openssl_err("BIO_new"))
    try:
        check(lib.PEM_write_bio_PrivateKey(bio, pkey, None, None, 0, None, None),
              "PEM_write_bio_PrivateKey")
        data = _bio_read(bio)
        with open(path, "wb") as f:
            f.write(data)
    finally:
        lib.BIO_free(bio)

def write_public_key(path: str, pkey):
    bio = lib.BIO_new(lib.BIO_s_mem())
    if not bio:
        raise RuntimeError(openssl_err("BIO_new"))
    try:
        check(lib.PEM_write_bio_PUBKEY(bio, pkey), "PEM_write_bio_PUBKEY")
        data = _bio_read(bio)
        with open(path, "wb") as f:
            f.write(data)
    finally:
        lib.BIO_free(bio)

# ─── key generation ─────────────────────────────────────────────────────

def generate_keypair(bits: int):
    if bits < 2048:
        raise ValueError(f"RSA key must be at least 2048 bits (requested {bits})")
    ctx = lib.EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, None)
    if not ctx:
        raise RuntimeError(openssl_err("EVP_PKEY_CTX_new_id"))
    try:
        check(lib.EVP_PKEY_keygen_init(ctx), "keygen_init")
        check(lib.EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits), "set_rsa_keygen_bits")
        pkey = c_void_p()
        check(lib.EVP_PKEY_keygen(ctx, byref(pkey)), "keygen")
        pub = c_void_p(pkey.value)
        lib.EVP_PKEY_up_ref(pub)
        return pkey, pub
    finally:
        lib.EVP_PKEY_CTX_free(ctx)

# ─── AES-256-GCM ───────────────────────────────────────────────────────

def aes_gcm_encrypt(plaintext: bytes, key: bytes, iv: bytes):
    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError(openssl_err("EVP_CIPHER_CTX_new"))
    try:
        check(lib.EVP_EncryptInit_ex(ctx, lib.EVP_aes_256_gcm(), None, key, iv),
              "EncryptInit_ex")
        out = create_string_buffer(len(plaintext) + 16)
        outlen = c_int()
        check(lib.EVP_EncryptUpdate(ctx, out, byref(outlen), plaintext, len(plaintext)),
              "EncryptUpdate")
        total = outlen.value
        outlen2 = c_int()
        check(lib.EVP_EncryptFinal_ex(ctx, out.raw, byref(outlen2)),
              "EncryptFinal_ex")
        tag = create_string_buffer(TAG_LEN)
        check(lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag),
              "CTRL_GCM_GET_TAG")
        return out.raw[:total + outlen2.value], tag.raw[:TAG_LEN]
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)

def aes_gcm_decrypt(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes):
    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError(openssl_err("EVP_CIPHER_CTX_new"))
    try:
        check(lib.EVP_DecryptInit_ex(ctx, lib.EVP_aes_256_gcm(), None, key, iv),
              "DecryptInit_ex")
        out = create_string_buffer(len(ciphertext) + 16)
        outlen = c_int()
        check(lib.EVP_DecryptUpdate(ctx, out, byref(outlen), ciphertext, len(ciphertext)),
              "DecryptUpdate")
        total = outlen.value
        check(lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag),
              "CTRL_GCM_SET_TAG")
        outlen2 = c_int()
        r = lib.EVP_DecryptFinal_ex(ctx, out.raw, byref(outlen2))
        if r != 1:
            raise RuntimeError("decryption failed: GCM authentication failed")
        return out.raw[:total + outlen2.value]
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)

# ─── high-level operations ─────────────────────────────────────────────

def encrypt_core(plaintext: bytes, priv_pkey):
    h = sha256(plaintext)
    seed = random_bytes(SEED_LEN)
    k = hmac_sha256(seed, h)
    iv = random_bytes(IV_LEN)
    ciphertext, tag = aes_gcm_encrypt(plaintext, k, iv)

    msg = seed + h + iv + tag
    sig = rsa_sign_raw(priv_pkey, msg)
    return sig, ciphertext

def decrypt_core(sig: bytes, ciphertext: bytes, pub_pkey):
    msg = rsa_verify_recover(pub_pkey, sig)
    if len(msg) < MESSAGE_LEN:
        raise ValueError(f"recovered message too short: need {MESSAGE_LEN}, got {len(msg)}")

    seed = msg[:SEED_LEN]
    h = msg[SEED_LEN:SEED_LEN + HASH_LEN]
    iv = msg[SEED_LEN + HASH_LEN:SEED_LEN + HASH_LEN + IV_LEN]
    tag = msg[SEED_LEN + HASH_LEN + IV_LEN:MESSAGE_LEN]

    k = hmac_sha256(seed, h)
    plaintext = aes_gcm_decrypt(ciphertext, k, iv, tag)

    computed_h = sha256(plaintext)
    if computed_h != h:
        raise RuntimeError("hash mismatch: decrypted content does not match original")
    return plaintext

# ─── file I/O ──────────────────────────────────────────────────────────

def read_input(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read()
    with open(path, "rb") as f:
        return f.read()

def write_output(path: str, data: bytes):
    if path == "-":
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    else:
        with open(path, "wb") as f:
            f.write(data)

def default_name(input_path: str, suffix: str, fallback: str) -> str:
    if input_path == "-":
        return fallback
    return input_path + suffix

# ─── CLI ───────────────────────────────────────────────────────────────

def cmd_genkey(args):
    p = argparse.ArgumentParser(prog="rsigner genkey")
    p.add_argument("-g", type=int, default=2048, help="RSA key bit length")
    p.add_argument("-k", default="private.pem", help="RSA private key PEM output")
    p.add_argument("-K", default="public.pem", help="RSA public key PEM output")
    opts = p.parse_args(args)

    priv, pub = generate_keypair(opts.g)
    try:
        write_private_key(opts.k, priv)
        write_public_key(opts.K, pub)
    finally:
        lib.EVP_PKEY_free(priv)
        lib.EVP_PKEY_free(pub)
    print("Done.", file=sys.stderr)

def cmd_encrypt(args):
    p = argparse.ArgumentParser(prog="rsigner encrypt")
    p.add_argument("-k", required=True, help="RSA private key PEM file")
    p.add_argument("-i", default="-", help="plaintext (default: stdin)")
    p.add_argument("-s", help="signature output (default: <input>.sig)")
    p.add_argument("-o", help="cipher output (default: <input>.rsn)")
    opts = p.parse_args(args)

    sig_path = opts.s or default_name(opts.i, ".sig", "sign.sig")
    out_path = opts.o or default_name(opts.i, ".rsn", "cipher.rsn")

    priv = read_private_key(opts.k)
    try:
        plaintext = read_input(opts.i)
        sig, ciphertext = encrypt_core(plaintext, priv)
        write_output(sig_path, sig)
        write_output(out_path, ciphertext)
    finally:
        lib.EVP_PKEY_free(priv)
    print("Done.", file=sys.stderr)

def cmd_decrypt(args):
    p = argparse.ArgumentParser(prog="rsigner decrypt")
    p.add_argument("-K", required=True, help="RSA public key PEM file")
    p.add_argument("-s", required=True, help="signature file")
    p.add_argument("-i", required=True, help="cipher file")
    p.add_argument("-o", help="plaintext output (default: strip .rsn)")
    opts = p.parse_args(args)

    if opts.o:
        out_path = opts.o
    else:
        if opts.i != "-" and opts.i.endswith(".rsn"):
            out_path = opts.i[:-4]
        else:
            out_path = "output.dec"

    pub = read_public_key(opts.K)
    try:
        sig = read_input(opts.s)
        ciphertext = read_input(opts.i)
        plaintext = decrypt_core(sig, ciphertext, pub)
        write_output(out_path, plaintext)
    finally:
        lib.EVP_PKEY_free(pub)
    print("Done.", file=sys.stderr)

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print("Usage: rsigner <command> [flags]", file=sys.stderr)
        print(file=sys.stderr)
        print("Commands:", file=sys.stderr)
        print("  genkey    Generate RSA key pair", file=sys.stderr)
        print("  encrypt   Encrypt file", file=sys.stderr)
        print("  decrypt   Decrypt file", file=sys.stderr)
        return

    cmds = {"genkey": cmd_genkey, "encrypt": cmd_encrypt, "decrypt": cmd_decrypt}
    if sys.argv[1] in cmds:
        cmds[sys.argv[1]](sys.argv[2:])
    else:
        print(f"Unknown command: {sys.argv[1]}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
