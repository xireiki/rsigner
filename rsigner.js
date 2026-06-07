/**
 * rsigner.js — RSA message recovery sign + AES-256-GCM encrypt/decrypt
 *
 * Pure JavaScript library using Web Crypto API (browser + Node.js 19+).
 *
 * All functions return Promises. Binary I/O uses Uint8Array.
 *
 * Key format:
 *   private → PKCS#8 PEM ("-----BEGIN PRIVATE KEY-----")
 *   public  → SPKI  PEM ("-----BEGIN PUBLIC KEY-----")
 *
 * Usage:
 *   import * as rsigner from './rsigner.js';
 *   const kp = await rsigner.generateKeyPair(2048);
 *   const { signature, ciphertext } = await rsigner.encrypt(plaintext, kp.privateKey);
 *   const decrypted = await rsigner.decrypt(signature, ciphertext, kp.publicKey);
 */

// ─── constants ───────────────────────────────────────────────────────────

const SEED_LEN = 32;
const HASH_LEN = 32;
const IV_LEN = 12;
const TAG_LEN = 16;
const MESSAGE_LEN = SEED_LEN + HASH_LEN + IV_LEN + TAG_LEN;

// ─── PEM utilities ───────────────────────────────────────────────────────

function derToPem(der, label) {
	const b64 = btoa(String.fromCharCode(...new Uint8Array(der)));
	const lines = b64.match(/.{1,64}/g) || [];
	return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

function pemToDer(pem) {
	const b64 = pem
		.split('\n')
		.map(l => l.trim())
		.filter(l => !l.startsWith('-----'))
		.join('');
	const raw = atob(b64);
	const bytes = new Uint8Array(raw.length);
	for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
	return bytes.buffer;
}

function detectPemLabel(pem) {
	const m = pem.match(/-----BEGIN\s+(\S+)\s*-----/);
	return m ? m[1] : null;
}

// ─── BigInt helpers ──────────────────────────────────────────────────────

function bytesToBigInt(bytes) {
	let n = 0n;
	for (const b of bytes) n = (n << 8n) + BigInt(b);
	return n;
}

function bigIntToBytes(n, minLen) {
	if (n === 0n) return new Uint8Array(Math.max(minLen, 1));
	const bytes = [];
	while (n > 0n) {
		bytes.unshift(Number(n & 0xFFn));
		n >>= 8n;
	}
	while (bytes.length < minLen) bytes.unshift(0);
	return new Uint8Array(bytes);
}

function modPow(base, exp, mod) {
	let r = 1n;
	base %= mod;
	while (exp > 0n) {
		if (exp & 1n) r = (r * base) % mod;
		exp >>= 1n;
		base = (base * base) % mod;
	}
	return r;
}

function base64UrlDecode(s) {
	return Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}

// ─── RSA PKCS#1 v1.5 padding ─────────────────────────────────────────────

function pkcs1v15Pad(msg, k) {
	if (msg.length + 11 > k) throw new Error('message too long for key size');
	const padLen = k - msg.length - 3;
	const block = new Uint8Array(k);
	block[0] = 0x00;
	block[1] = 0x01;
	block.fill(0xFF, 2, 2 + padLen);
	block[2 + padLen] = 0x00;
	block.set(msg, 2 + padLen + 1);
	return block;
}

function pkcs1v15Unpad(block) {
	if (block[0] !== 0x00 || block[1] !== 0x01) throw new Error('invalid RSA padding: missing 0x0001 prefix');
	let i = 2;
	while (i < block.length && block[i] === 0xFF) i++;
	if (i >= block.length || block[i] !== 0x00) throw new Error('invalid RSA padding: missing 0x00 separator');
	if (i - 2 < 8) throw new Error('RSA padding too short (< 8 bytes)');
	const msg = block.slice(i + 1);
	if (msg.length === 0) throw new Error('recovered message is empty');
	return msg;
}

// ─── RSA raw sign / verify-recover ────────────────────────────────────────

async function getPrivComponents(key) {
	const j = await crypto.subtle.exportKey('jwk', key);
	return {
		n: bytesToBigInt(base64UrlDecode(j.n)),
		e: bytesToBigInt(base64UrlDecode(j.e)),
		d: bytesToBigInt(base64UrlDecode(j.d)),
	};
}

async function getPubComponents(key) {
	const j = await crypto.subtle.exportKey('jwk', key);
	return {
		n: bytesToBigInt(base64UrlDecode(j.n)),
		e: bytesToBigInt(base64UrlDecode(j.e)),
	};
}

function rsaSignRaw(comp, msg) {
	const k = bigIntToBytes(comp.n).length;
	const padded = pkcs1v15Pad(msg, k);
	const m = bytesToBigInt(padded);
	const s = modPow(m, comp.d, comp.n);
	return bigIntToBytes(s, k);
}

function rsaVerifyRecover(comp, sig) {
	const k = bigIntToBytes(comp.n).length;
	if (sig.length !== k) throw new Error(`signature length mismatch: got ${sig.length}, want ${k}`);
	const si = bytesToBigInt(sig);
	const mi = modPow(si, comp.e, comp.n);
	const em = bigIntToBytes(mi, k);
	return pkcs1v15Unpad(em);
}

// ─── RSA key I/O ─────────────────────────────────────────────────────────

/**
 * Generate an RSA key pair.
 * @param {number} bits - key size (default 2048)
 * @returns {Promise<CryptoKeyPair>} { privateKey, publicKey }
 */
export async function generateKeyPair(bits = 2048) {
	if (bits < 2048) throw new Error(`RSA key must be at least 2048 bits (requested ${bits})`);
	return crypto.subtle.generateKey(
		{ name: 'RSASSA-PKCS1-v1_5', modulusLength: bits, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: 'SHA-256' },
		true,
		['sign', 'verify']
	);
}

/**
 * Export private key to PKCS#8 PEM string.
 * @param {CryptoKey} key
 * @returns {Promise<string>}
 */
export async function exportPrivateKey(key) {
	const der = await crypto.subtle.exportKey('pkcs8', key);
	return derToPem(der, 'PRIVATE KEY');
}

/**
 * Export public key to SPKI PEM string.
 * @param {CryptoKey} key
 * @returns {Promise<string>}
 */
export async function exportPublicKey(key) {
	const der = await crypto.subtle.exportKey('spki', key);
	return derToPem(der, 'PUBLIC KEY');
}

/**
 * Import private key from PEM string.
 * Supports PKCS#8 ("PRIVATE KEY") and PKCS#1 ("RSA PRIVATE KEY").
 * @param {string} pem
 * @returns {Promise<CryptoKey>}
 */
export async function importPrivateKey(pem) {
	const label = detectPemLabel(pem);
	const der = pemToDer(pem);

	if (label === 'RSA PRIVATE KEY') {
		// PKCS#1 → wrap into PKCS#8 for Web Crypto
		const wrapped = pkcs1ToPkcs8(new Uint8Array(der));
		return crypto.subtle.importKey(
			'pkcs8', wrapped.buffer,
			{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
			true, ['sign']
		);
	}
	// PKCS#8
	return crypto.subtle.importKey(
		'pkcs8', der,
		{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
		true, ['sign']
	);
}

/**
 * Import public key from PEM string (SPKI format, "PUBLIC KEY").
 * @param {string} pem
 * @returns {Promise<CryptoKey>}
 */
export async function importPublicKey(pem) {
	const der = pemToDer(pem);
	return crypto.subtle.importKey(
		'spki', der,
		{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
		true, ['verify']
	);
}

// ─── PKCS#1 → PKCS#8 wrapper ─────────────────────────────────────────────

/**
 * Minimal ASN.1 DER wrapper: PKCS#1 → PKCS#8.
 * PKCS#8 = SEQUENCE { version(0), AlgorithmIdentifier, RSA private key (PKCS#1) }
 */
function pkcs1ToPkcs8(pkcs1Der) {
	// AlgorithmIdentifier for RSA: SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }
	const algId = new Uint8Array([
		0x30, 0x0d, // SEQUENCE (13 bytes)
			0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, // OID rsaEncryption
			0x05, 0x00, // NULL
	]);

	// Build PKCS#8: SEQUENCE { INTEGER 0, algId, OCTET STRING (PKCS#1 DER) }
	const inner = pkcs1Der;
	const innerTag = derWrap(0x04, inner); // OCTET STRING

	const body = new Uint8Array([0x02, 0x01, 0x00, ...algId, ...innerTag]); // INTEGER 0 + algId + OCTET STRING
	return derWrap(0x30, body); // SEQUENCE
}

function derWrap(tag, content) {
	const len = content.length;
	let header;
	if (len < 0x80) {
		header = new Uint8Array([tag, len]);
	} else if (len < 0x100) {
		header = new Uint8Array([tag, 0x81, len]);
	} else if (len < 0x10000) {
		header = new Uint8Array([tag, 0x82, (len >> 8) & 0xff, len & 0xff]);
	} else {
		throw new Error('DER length too large');
	}
	const result = new Uint8Array(header.length + len);
	result.set(header);
	result.set(content, header.length);
	return result;
}

// ─── crypto helpers (SHA-256, HMAC, AES-GCM, random) ──────────────────────

function randomBytes(n) {
	const buf = new Uint8Array(n);
	crypto.getRandomValues(buf);
	return buf;
}

async function sha256(data) {
	return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

async function hmacSha256(key, data) {
	const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	return new Uint8Array(await crypto.subtle.sign('HMAC', k, data));
}

async function aesGcmEncrypt(plaintext, key, iv) {
	const k = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
	const result = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, k, plaintext));
	const tag = result.slice(-TAG_LEN);
	const ciphertext = result.slice(0, -TAG_LEN);
	return { ciphertext, tag };
}

async function aesGcmDecrypt(ciphertext, key, iv, tag) {
	const k = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
	const combined = new Uint8Array(ciphertext.length + TAG_LEN);
	combined.set(ciphertext);
	combined.set(tag, ciphertext.length);
	return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, k, combined));
}

// ─── high-level encrypt / decrypt ─────────────────────────────────────────

/**
 * Encrypt plaintext with RSA private key.
 *
 * @param {Uint8Array} plaintext
 * @param {CryptoKey} privateKey  (must be extractable)
 * @returns {Promise<{ signature: Uint8Array, ciphertext: Uint8Array }>}
 */
export async function encrypt(plaintext, privateKey) {
	const h = await sha256(plaintext);
	const seed = randomBytes(SEED_LEN);
	const k = await hmacSha256(seed, h);
	const iv = randomBytes(IV_LEN);
	const { ciphertext, tag } = await aesGcmEncrypt(plaintext, k, iv);

	const msg = new Uint8Array(MESSAGE_LEN);
	msg.set(seed, 0);
	msg.set(h, SEED_LEN);
	msg.set(iv, SEED_LEN + HASH_LEN);
	msg.set(tag, SEED_LEN + HASH_LEN + IV_LEN);

	const comp = await getPrivComponents(privateKey);
	const signature = rsaSignRaw(comp, msg);

	return { signature, ciphertext };
}

/**
 * Decrypt ciphertext with RSA public key.
 *
 * @param {Uint8Array} signature
 * @param {Uint8Array} ciphertext
 * @param {CryptoKey} publicKey  (must be extractable)
 * @returns {Promise<Uint8Array>}
 */
export async function decrypt(signature, ciphertext, publicKey) {
	const comp = await getPubComponents(publicKey);
	const msg = rsaVerifyRecover(comp, signature);

	if (msg.length < MESSAGE_LEN) throw new Error(`recovered message too short: need ${MESSAGE_LEN}, got ${msg.length}`);

	const seed = msg.slice(0, SEED_LEN);
	const h = msg.slice(SEED_LEN, SEED_LEN + HASH_LEN);
	const iv = msg.slice(SEED_LEN + HASH_LEN, SEED_LEN + HASH_LEN + IV_LEN);
	const tag = msg.slice(SEED_LEN + HASH_LEN + IV_LEN, MESSAGE_LEN);

	const k = await hmacSha256(seed, h);
	const plaintext = await aesGcmDecrypt(ciphertext, k, iv, tag);

	const computedH = await sha256(plaintext);
	if (computedH.length !== h.length || !computedH.every((b, i) => b === h[i])) {
		throw new Error('hash mismatch: decrypted content does not match original');
	}

	return plaintext;
}
