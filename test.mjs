#!/usr/bin/env node
// Quick test for rsigner.js using Node.js Web Crypto API
import * as r from './rsigner.js';
import { TextEncoder, TextDecoder } from 'util';

async function main() {
	// Generate key pair
	const kp = await r.generateKeyPair(2048);
	console.log('✓ generateKeyPair');

	// Export/import round-trip
	const privPem = await r.exportPrivateKey(kp.privateKey);
	const pubPem = await r.exportPublicKey(kp.publicKey);
	console.log('✓ export PEM');

	const priv2 = await r.importPrivateKey(privPem);
	const pub2 = await r.importPublicKey(pubPem);
	console.log('✓ import PEM');

	// Encrypt
	const plaintext = new TextEncoder().encode('hello rsigner.js');
	const { signature, ciphertext } = await r.encrypt(plaintext, priv2);
	console.log(`✓ encrypt: sig=${signature.length}B ct=${ciphertext.length}B`);

	// Decrypt
	const decrypted = await r.decrypt(signature, ciphertext, pub2);
	const text = new TextDecoder().decode(decrypted);
	console.log(`✓ decrypt: "${text}"`);

	// Verify
	if (text !== 'hello rsigner.js') throw new Error('mismatch!');
	console.log('✓ PASS');
}

main().catch(e => { console.error('FAIL:', e); process.exit(1); });
