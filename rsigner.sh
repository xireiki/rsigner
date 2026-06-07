#!/bin/sh
# rsigner — RSA message recovery sign + AES-256-GCM encrypt/decrypt
# Shell implementation using openssl CLI + aesgcm helper
set -e

die() { echo "Error: $*" >&2; exit 1; }

# ─── genkey ────────────────────────────────────────────────────────────

genkey() {
	bits=2048; priv="private.pem"; pub="public.pem"
	while getopts "g:k:K:h" o; do
		case "$o" in g) bits=$OPTARG;; k) priv=$OPTARG;; K) pub=$OPTARG;;
			h) echo "Usage: rsigner genkey [-g bits] [-k priv] [-K pub]"; return 0;;
			?) echo "Usage: rsigner genkey [-g bits] [-k priv] [-K pub]" >&2; return 1;;
		esac
	done
	openssl genpkey -algorithm RSA -out "$priv" -pkeyopt rsa_keygen_bits:"$bits"
	openssl pkey -in "$priv" -pubout -out "$pub"
	echo "Done." >&2
}

# ─── encrypt ───────────────────────────────────────────────────────────

encrypt() {
	priv=; input=-; sig=; cipher=
	while getopts "k:i:s:o:h" o; do
		case "$o" in k) priv=$OPTARG;; i) input=$OPTARG;; s) sig=$OPTARG;; o) cipher=$OPTARG;;
			h) echo "Usage: rsigner encrypt -k privkey [-i input] [-s sig] [-o out]"; return 0;;
			?) echo "Usage: rsigner encrypt -k privkey [-i input] [-s sig] [-o out]" >&2; return 1;;
		esac
	done
	[ -n "$priv" ] || die "encrypt requires -k/--private-key"

	# default output paths
	[ -n "$sig" ]    || { [ "$input" = "-" ] && sig="sign.sig"    || sig="${input}.sig"; }
	[ -n "$cipher" ] || { [ "$input" = "-" ] && cipher="cipher.rsn" || cipher="${input}.rsn"; }

	td=$(mktemp -d) || die "mktemp failed"
	trap 'rm -rf "$td"' EXIT

	# read input (stdin -> temp file if pipe)
	if [ "$input" = "-" ]; then
		input="$td/plain"
		cat > "$input"
	fi

	H=$(openssl dgst -sha256 -binary "$input" | xxd -p -c 32)
	S=$(openssl rand 32 | xxd -p -c 32)

	# K = HMAC-SHA256(S, H)
	K=$(printf "%s" "$S" | xxd -r -p | openssl dgst -sha256 -mac hmac -macopt hexkey:"$S" -binary | xxd -p -c 32)

	IV=$(openssl rand 12 | xxd -p -c 12)

	# AES-256-GCM encrypt via aesgcm helper
	./aesgcm e "$K" "$IV" "$td/tag" < "$input" > "$td/cipher"
	TAG=$(cat "$td/tag")

	# M = S || H || IV || Tag
	printf "%s%s%s%s" "$S" "$H" "$IV" "$TAG" | xxd -r -p > "$td/M"

	# RSA raw sign (PKCS#1 v1.5 message recovery)
	openssl rsautl -sign -in "$td/M" -inkey "$priv" -out "$sig"

	# output cipher
	if [ "$cipher" = "-" ]; then
		cat "$td/cipher"
	else
		cp "$td/cipher" "$cipher"
	fi

	echo "Done." >&2
}

# ─── decrypt ───────────────────────────────────────────────────────────

decrypt() {
	pub=; sig=; cipher=; plain=
	while getopts "K:s:i:o:h" o; do
		case "$o" in K) pub=$OPTARG;; s) sig=$OPTARG;; i) cipher=$OPTARG;; o) plain=$OPTARG;;
			h) echo "Usage: rsigner decrypt -K pubkey -s sig -i input [-o out]"; return 0;;
			?) echo "Usage: rsigner decrypt -K pubkey -s sig -i input [-o out]" >&2; return 1;;
		esac
	done
	[ -n "$pub" ]    || die "decrypt requires -K/--public-key"
	[ -n "$sig" ]    || die "decrypt requires -s/--sign"
	[ -n "$cipher" ] || die "decrypt requires -i/--input"

	# default output path
	if [ -z "$plain" ]; then
		if [ "$cipher" = "-" ]; then
			plain="output.dec"
		else
			case "$cipher" in
				*.rsn) plain="${cipher%.rsn}";;
				*)     plain="output.dec";;
			esac
		fi
	fi

	td=$(mktemp -d) || die "mktemp failed"
	trap 'rm -rf "$td"' EXIT

	# read cipher from stdin if needed
	if [ "$cipher" = "-" ]; then
		cipher="$td/cipher"
		cat > "$cipher"
	fi

	# RSA verify recover → M = S || H || IV || Tag
	openssl rsautl -verify -in "$sig" -inkey "$pub" -pubin -out "$td/M"

	# parse fields
	S=$(dd if="$td/M" bs=32 count=1 2>/dev/null | xxd -p -c 32)
	H=$(dd if="$td/M" bs=32 skip=1 count=1 2>/dev/null | xxd -p -c 32)
	IV=$(dd if="$td/M" bs=1 skip=64 count=12 2>/dev/null | xxd -p -c 12)
	TAG=$(dd if="$td/M" bs=1 skip=76 count=16 2>/dev/null | xxd -p -c 16)

	# K = HMAC-SHA256(S, H)
	K=$(printf "%s" "$S" | xxd -r -p | openssl dgst -sha256 -mac hmac -macopt hexkey:"$S" -binary | xxd -p -c 32)

	# decrypt via aesgcm helper
	printf "%s" "$TAG" > "$td/tag"
	./aesgcm d "$K" "$IV" "$td/tag" < "$cipher" > "$td/plain"

	# verify hash
	COMPUTED_H=$(openssl dgst -sha256 -binary "$td/plain" | xxd -p -c 32)
	[ "$COMPUTED_H" = "$H" ] || die "hash mismatch: decrypted content does not match original"

	# output
	if [ "$plain" = "-" ]; then
		cat "$td/plain"
	else
		cp "$td/plain" "$plain"
	fi

	echo "Done." >&2
}

# ─── main ──────────────────────────────────────────────────────────────

main() {
	[ $# -ge 1 ] || { echo "Usage: rsigner <command> [flags]" >&2; exit 1; }
	cmd=$1; shift
	case "$cmd" in
		genkey)  genkey "$@" ;;
		encrypt) encrypt "$@" ;;
		decrypt) decrypt "$@" ;;
		help|-h|--help)
			echo "Usage: rsigner <command> [flags]"
			echo ""
			echo "Commands:"
			echo "  genkey    Generate RSA key pair"
			echo "  encrypt   Encrypt file"
			echo "  decrypt   Decrypt file"
			echo "Run 'rsigner <command> -h' for command-specific help." ;;
		*) die "Unknown command: $cmd";;
	esac
}

main "$@"
