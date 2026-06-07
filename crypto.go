package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
)

const (
	SeedLen    = 32 
	HashLen    = 32 
	IVLen      = 12 
	TagLen     = 16 
	MessageLen = SeedLen + HashLen + IVLen + TagLen
)

func deriveKey(seed, fileHash []byte) []byte {
	mac := hmac.New(sha256.New, seed)
	mac.Write(fileHash)
	return mac.Sum(nil)
}

func aesGCMEncrypt(plaintext, key, iv []byte) (ciphertext, tag []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	out := aesGCM.Seal(nil, iv, plaintext, nil)
	tag = out[len(out)-TagLen:]
	ciphertext = out[:len(out)-TagLen]
	return
}

func aesGCMDecrypt(ciphertext, key, iv, tag []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	combined := make([]byte, len(ciphertext)+len(tag))
	copy(combined, ciphertext)
	copy(combined[len(ciphertext):], tag)
	plaintext, err := aesGCM.Open(nil, iv, combined, nil)
	if err != nil {
		return nil, fmt.Errorf("GCM authentication failed: %w", err)
	}
	return plaintext, nil
}

func rsaSignRaw(priv *rsa.PrivateKey, msg []byte) ([]byte, error) {
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.Hash(0), msg)
	if err != nil {
		return nil, fmt.Errorf("rsa.SignPKCS1v15: %w", err)
	}
	return sig, nil
}

func rsaVerifyRecover(pub *rsa.PublicKey, sig []byte) ([]byte, error) {
	k := pub.Size()
	if len(sig) != k {
		return nil, errors.New("signature length does not match modulus")
	}
	sigInt := new(big.Int).SetBytes(sig)
	if sigInt.Cmp(pub.N) >= 0 {
		return nil, errors.New("signature value exceeds modulus")
	}
	mInt := new(big.Int).Exp(sigInt, big.NewInt(int64(pub.E)), pub.N)
	em := make([]byte, k)
	mInt.FillBytes(em)
	if em[0] != 0x00 || em[1] != 0x01 {
		return nil, errors.New("invalid RSA padding: missing 0x0001 prefix")
	}
	i := 2
	for i < len(em) && em[i] == 0xFF {
		i++
	}
	if i >= len(em) || em[i] != 0x00 {
		return nil, errors.New("invalid RSA padding: missing 0x00 separator")
	}
	if i-2 < 8 {
		return nil, errors.New("RSA padding too short (< 8 bytes)")
	}
	msg := em[i+1:]
	if len(msg) == 0 {
		return nil, errors.New("recovered message is empty")
	}
	return msg, nil
}

func ReadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("PEM decode failed")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
	}
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("key is not an RSA private key")
	}
	return priv, nil
}

func ReadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("PEM decode failed")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not an RSA public key")
	}
	return pub, nil
}

func WritePrivateKey(path string, priv *rsa.PrivateKey) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create private key file: %w", err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}); err != nil {
		return fmt.Errorf("write private key PEM: %w", err)
	}
	return nil
}

func WritePublicKey(path string, pub *rsa.PublicKey) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create public key file: %w", err)
	}
	defer f.Close()
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("encode public key: %w", err)
	}
	if err := pem.Encode(f, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubBytes,
	}); err != nil {
		return fmt.Errorf("write public key PEM: %w", err)
	}
	return nil
}

// EncryptCore performs the core encryption: given plaintext bytes and an RSA
// private key, returns (signature, ciphertext). Does no file I/O.
func EncryptCore(plaintext []byte, priv *rsa.PrivateKey) (sig, ciphertext []byte, err error) {
	h := sha256.Sum256(plaintext)
	seed := make([]byte, SeedLen)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, nil, fmt.Errorf("generate seed: %w", err)
	}
	k := deriveKey(seed, h[:])
	iv := make([]byte, IVLen)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, fmt.Errorf("generate IV: %w", err)
	}
	ciphertext, tag, err := aesGCMEncrypt(plaintext, k, iv)
	if err != nil {
		return nil, nil, fmt.Errorf("AES-GCM encrypt: %w", err)
	}
	msg := make([]byte, MessageLen)
	copy(msg[0:SeedLen], seed)
	copy(msg[SeedLen:SeedLen+HashLen], h[:])
	copy(msg[SeedLen+HashLen:SeedLen+HashLen+IVLen], iv)
	copy(msg[SeedLen+HashLen+IVLen:], tag)
	sig, err = rsaSignRaw(priv, msg)
	if err != nil {
		return nil, nil, fmt.Errorf("RSA sign: %w", err)
	}
	return sig, ciphertext, nil
}

// DecryptCore performs the core decryption: given signature and ciphertext bytes
// and an RSA public key, returns the plaintext. Does no file I/O.
func DecryptCore(sig, ciphertext []byte, pub *rsa.PublicKey) ([]byte, error) {
	msg, err := rsaVerifyRecover(pub, sig)
	if err != nil {
		return nil, fmt.Errorf("signature verify/recover: %w", err)
	}
	if len(msg) < MessageLen {
		return nil, fmt.Errorf("recovered message too short: need %d, got %d", MessageLen, len(msg))
	}
	seed := msg[0:SeedLen]
	h := msg[SeedLen : SeedLen+HashLen]
	iv := msg[SeedLen+HashLen : SeedLen+HashLen+IVLen]
	tag := msg[SeedLen+HashLen+IVLen : MessageLen]
	k := deriveKey(seed, h)
	plaintext, err := aesGCMDecrypt(ciphertext, k, iv, tag)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	computedH := sha256.Sum256(plaintext)
	if !hmac.Equal(computedH[:], h) {
		return nil, errors.New("hash mismatch: decrypted content does not match original")
	}
	return plaintext, nil
}

// EncryptFile reads plaintext from a file, encrypts, and writes sig+ciphertext to files.
func EncryptFile(plainPath, sigPath, cipherPath string, priv *rsa.PrivateKey) error {
	plaintext, err := os.ReadFile(plainPath)
	if err != nil {
		return fmt.Errorf("read plaintext: %w", err)
	}
	sig, ciphertext, err := EncryptCore(plaintext, priv)
	if err != nil {
		return err
	}
	if err := os.WriteFile(sigPath, sig, 0644); err != nil {
		return fmt.Errorf("write signature: %w", err)
	}
	if err := os.WriteFile(cipherPath, ciphertext, 0644); err != nil {
		return fmt.Errorf("write ciphertext: %w", err)
	}
	return nil
}

// DecryptFile reads sig+ciphertext from files, decrypts, and writes plaintext to a file.
func DecryptFile(sigPath, cipherPath, plainPath string, pub *rsa.PublicKey) error {
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("read signature: %w", err)
	}
	ciphertext, err := os.ReadFile(cipherPath)
	if err != nil {
		return fmt.Errorf("read ciphertext: %w", err)
	}
	plaintext, err := DecryptCore(sig, ciphertext, pub)
	if err != nil {
		return err
	}
	if err := os.WriteFile(plainPath, plaintext, 0644); err != nil {
		return fmt.Errorf("write plaintext: %w", err)
	}
	return nil
}

func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	if bits < 2048 {
		return nil, nil, fmt.Errorf("RSA key must be at least 2048 bits (requested %d)", bits)
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("generate %d-bit RSA key: %w", bits, err)
	}
	return priv, &priv.PublicKey, nil
}
