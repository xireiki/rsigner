use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use clap::{Parser, Subcommand};
use hmac::Mac;
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::DecodePrivateKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::pkcs8::EncodePublicKey;

use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read, Write};

const SEED_LEN: usize = 32;
const HASH_LEN: usize = 32;
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MESSAGE_LEN: usize = SEED_LEN + HASH_LEN + IV_LEN + TAG_LEN;

// ─── CLI ────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "rsigner", about = "RSA message recovery sign + AES-256-GCM encrypt/decrypt")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate RSA key pair
    Genkey {
        #[arg(short = 'g', default_value = "2048")]
        bits: usize,
        #[arg(short = 'k', default_value = "private.pem")]
        priv_out: String,
        #[arg(short = 'K', default_value = "public.pem")]
        pub_out: String,
    },
    /// Encrypt file
    Encrypt {
        #[arg(short = 'k')]
        priv_key: String,
        #[arg(short = 'i', default_value = "-")]
        input: String,
        #[arg(short = 's')]
        sig_out: Option<String>,
        #[arg(short = 'o')]
        cipher_out: Option<String>,
    },
    /// Decrypt file
    Decrypt {
        #[arg(short = 'K')]
        pub_key: String,
        #[arg(short = 's')]
        sig_in: String,
        #[arg(short = 'i')]
        cipher_in: String,
        #[arg(short = 'o')]
        plain_out: Option<String>,
    },
}

// ─── helpers ─────────────────────────────────────────────────────────────

fn sha256_hash(data: &[u8]) -> [u8; HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; HASH_LEN] {
    let mut mac = <hmac::Hmac::<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

// ─── RSA message recovery ───────────────────────────────────────────────

fn rsa_sign_raw(priv_key: &RsaPrivateKey, msg: &[u8]) -> Vec<u8> {
    let mut rng = OsRng;
    priv_key
        .sign_with_rng(&mut rng, Pkcs1v15Sign::new_unprefixed(), msg)
        .expect("RSA sign failed")
}

fn rsa_verify_recover(pub_key: &RsaPublicKey, sig: &[u8]) -> Vec<u8> {
    let k = pub_key.size();
    if sig.len() != k {
        panic!(
            "signature length does not match modulus: got {}, want {}",
            sig.len(),
            k
        );
    }

    let sig_int = rsa::BigUint::from_bytes_be(sig);
    let m_int = sig_int.modpow(pub_key.e(), pub_key.n());
    let mut em = m_int.to_bytes_be();

    // Pad to k bytes
    if em.len() < k {
        let mut padded = vec![0u8; k - em.len()];
        padded.append(&mut em);
        em = padded;
    }

    // Parse PKCS#1 v1.5 padding: 00 01 FF ... FF 00 MESSAGE
    if em.len() < 3 || em[0] != 0 || em[1] != 1 {
        panic!("invalid RSA padding: missing 0x0001 prefix");
    }
    let mut i = 2;
    while i < em.len() && em[i] == 0xFF {
        i += 1;
    }
    if i >= em.len() || em[i] != 0x00 {
        panic!("invalid RSA padding: missing 0x00 separator");
    }
    if i - 2 < 8 {
        panic!("RSA padding too short (< 8 bytes)");
    }
    let msg = em[i + 1..].to_vec();
    if msg.is_empty() {
        panic!("recovered message is empty");
    }
    msg
}

// ─── PEM I/O ─────────────────────────────────────────────────────────────

fn read_private_key(path: &str) -> RsaPrivateKey {
    let pem = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {}", path, e));
    RsaPrivateKey::from_pkcs1_pem(&pem)
        .or_else(|_| RsaPrivateKey::from_pkcs8_pem(&pem))
        .unwrap_or_else(|e| panic!("parse private key: {}", e))
}

fn read_public_key(path: &str) -> RsaPublicKey {
    let pem = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {}", path, e));
    RsaPublicKey::from_public_key_pem(&pem).unwrap_or_else(|e| panic!("parse public key: {}", e))
}

fn write_private_key(path: &str, key: &RsaPrivateKey) {
    let pem = key
        .to_pkcs1_pem(Default::default())
        .expect("encode private key");
    fs::write(path, pem.as_bytes()).unwrap_or_else(|e| panic!("write {}: {}", path, e));
}

fn write_public_key(path: &str, key: &RsaPublicKey) {
    let pem = key
        .to_public_key_pem(Default::default())
        .expect("encode public key");
    fs::write(path, pem.as_bytes()).unwrap_or_else(|e| panic!("write {}: {}", path, e));
}

// ─── AES-256-GCM ─────────────────────────────────────────────────────────

fn aes_gcm_encrypt(plaintext: &[u8], key: &[u8; 32], iv: &[u8; 12]) -> (Vec<u8>, [u8; TAG_LEN]) {
    let cipher = Aes256Gcm::new_from_slice(key).expect("valid key");
    let nonce = Nonce::from_slice(iv);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("AES-GCM encrypt failed");
    let tag: [u8; TAG_LEN] = ciphertext[ciphertext.len() - TAG_LEN..].try_into().unwrap();
    let ct = ciphertext[..ciphertext.len() - TAG_LEN].to_vec();
    (ct, tag)
}

fn aes_gcm_decrypt(
    ciphertext: &[u8],
    key: &[u8; 32],
    iv: &[u8; 12],
    tag: &[u8; TAG_LEN],
) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("valid key");
    let nonce = Nonce::from_slice(iv);
    let mut combined = ciphertext.to_vec();
    combined.extend_from_slice(tag);
    cipher
        .decrypt(nonce, combined.as_ref())
        .expect("GCM authentication failed")
}

// ─── high-level operations ──────────────────────────────────────────────

fn encrypt_core(plaintext: &[u8], priv_key: &RsaPrivateKey) -> (Vec<u8>, Vec<u8>) {
    let h = sha256_hash(plaintext);
    let seed: [u8; SEED_LEN] = random_bytes();
    let k = hmac_sha256(&seed, &h);
    let iv: [u8; IV_LEN] = random_bytes();
    let (ciphertext, tag) = aes_gcm_encrypt(plaintext, &k, &iv);

    let mut msg = Vec::with_capacity(MESSAGE_LEN);
    msg.extend_from_slice(&seed);
    msg.extend_from_slice(&h);
    msg.extend_from_slice(&iv);
    msg.extend_from_slice(&tag);

    let sig = rsa_sign_raw(priv_key, &msg);
    (sig, ciphertext)
}

fn decrypt_core(sig: &[u8], ciphertext: &[u8], pub_key: &RsaPublicKey) -> Vec<u8> {
    let msg = rsa_verify_recover(pub_key, sig);
    if msg.len() < MESSAGE_LEN {
        panic!(
            "recovered message too short: need {}, got {}",
            MESSAGE_LEN,
            msg.len()
        );
    }

    let seed: &[u8; SEED_LEN] = msg[..SEED_LEN].try_into().unwrap();
    let h: &[u8; HASH_LEN] = msg[SEED_LEN..SEED_LEN + HASH_LEN].try_into().unwrap();
    let iv: &[u8; IV_LEN] = msg[SEED_LEN + HASH_LEN..SEED_LEN + HASH_LEN + IV_LEN]
        .try_into()
        .unwrap();
    let tag: &[u8; TAG_LEN] = msg[MESSAGE_LEN - TAG_LEN..MESSAGE_LEN].try_into().unwrap();

    let k = hmac_sha256(seed, h);
    let plaintext = aes_gcm_decrypt(ciphertext, &k, iv, tag);

    let computed_h = sha256_hash(&plaintext);
    if computed_h != *h {
        panic!("hash mismatch: decrypted content does not match original");
    }
    plaintext
}

// ─── file I/O ───────────────────────────────────────────────────────────

fn read_input(path: &str) -> Vec<u8> {
    if path == "-" {
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .expect("read stdin failed");
        buf
    } else {
        fs::read(path).unwrap_or_else(|e| panic!("read {}: {}", path, e))
    }
}

fn write_output(path: &str, data: &[u8]) {
    if path == "-" {
        io::stdout()
            .write_all(data)
            .expect("write stdout failed");
        io::stdout().flush().ok();
    } else {
        fs::write(path, data).unwrap_or_else(|e| panic!("write {}: {}", path, e));
    }
}

fn default_name(input: &str, suffix: &str, fallback: &str) -> String {
    if input == "-" {
        fallback.to_string()
    } else {
        format!("{}{}", input, suffix)
    }
}

// ─── commands ───────────────────────────────────────────────────────────

fn cmd_genkey(bits: usize, priv_out: &str, pub_out: &str) {
    if bits < 2048 {
        panic!("RSA key must be at least 2048 bits (requested {})", bits);
    }
    let mut rng = OsRng;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("RSA key generation failed");
    let pub_key = priv_key.to_public_key();
    write_private_key(priv_out, &priv_key);
    write_public_key(pub_out, &pub_key);
    eprintln!("Done.");
}

fn cmd_encrypt(priv_key_path: &str, input: &str, sig_out: Option<&str>, cipher_out: Option<&str>) {
    let sig_path = sig_out
        .map(|s| s.to_string())
        .unwrap_or_else(|| default_name(input, ".sig", "sign.sig"));
    let out_path = cipher_out
        .map(|s| s.to_string())
        .unwrap_or_else(|| default_name(input, ".rsn", "cipher.rsn"));

    let priv_key = read_private_key(priv_key_path);
    let plaintext = read_input(input);
    let (sig, ciphertext) = encrypt_core(&plaintext, &priv_key);
    write_output(&sig_path, &sig);
    write_output(&out_path, &ciphertext);
    eprintln!("Done.");
}

fn cmd_decrypt(pub_key_path: &str, sig_in: &str, cipher_in: &str, plain_out: Option<&str>) {
    let out_path = match plain_out {
        Some(s) => s.to_string(),
        None => {
            if cipher_in != "-" && cipher_in.ends_with(".rsn") {
                cipher_in[..cipher_in.len() - 4].to_string()
            } else {
                "output.dec".to_string()
            }
        }
    };

    let pub_key = read_public_key(pub_key_path);
    let sig = read_input(sig_in);
    let ciphertext = read_input(cipher_in);
    let plaintext = decrypt_core(&sig, &ciphertext, &pub_key);
    write_output(&out_path, &plaintext);
    eprintln!("Done.");
}

// ─── main ───────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Genkey {
            bits,
            priv_out,
            pub_out,
        } => cmd_genkey(bits, &priv_out, &pub_out),
        Command::Encrypt {
            priv_key,
            input,
            sig_out,
            cipher_out,
        } => cmd_encrypt(&priv_key, &input, sig_out.as_deref(), cipher_out.as_deref()),
        Command::Decrypt {
            pub_key,
            sig_in,
            cipher_in,
            plain_out,
        } => cmd_decrypt(&pub_key, &sig_in, &cipher_in, plain_out.as_deref()),
    }
}
