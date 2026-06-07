package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	privKeyFile string
	pubKeyFile  string
	inputFile   string
	outputFile  string
	signFile    string
	genrsaBits  int
)

var rootCmd = &cobra.Command{
	Use:   "rsigner",
	Short: "RSA message recovery sign + AES-256-GCM encrypt/decrypt",
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&privKeyFile, "private-key", "k", "", "RSA private key PEM file")
	rootCmd.PersistentFlags().StringVarP(&pubKeyFile, "public-key", "K", "", "RSA public key PEM file")

	// ── genkey ────────────────────────────────────────────────────────
	var genkeyCmd = &cobra.Command{
		Use:   "genkey",
		Short: "Generate RSA key pair",
		Run: func(cmd *cobra.Command, args []string) {
			if genrsaBits == 0 {
				genrsaBits = 2048
			}
			if privKeyFile == "" {
				privKeyFile = "private.pem"
			}
			if pubKeyFile == "" {
				pubKeyFile = "public.pem"
			}
			if err := runGenKey(genrsaBits, privKeyFile, pubKeyFile); err != nil {
				die("Failed: %v", err)
			}
			fmt.Fprintln(os.Stderr, "Done.")
		},
	}
	genkeyCmd.Flags().IntVarP(&genrsaBits, "genrsa", "g", 0, "RSA key bit length (2048/3072/4096), default 2048")
	rootCmd.AddCommand(genkeyCmd)

	// ── encrypt ────────────────────────────────────────────────────────
	var encryptCmd = &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt file",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if privKeyFile == "" {
				return errors.New("encrypt requires -k/--private-key")
			}
			if inputFile == "" {
				inputFile = "-"
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			if signFile == "" {
				signFile = defaultName(inputFile, ".sig", "sign.sig")
			}
			if outputFile == "" {
				outputFile = defaultName(inputFile, ".rsn", "cipher.rsn")
			}
			if err := runEncrypt(privKeyFile, inputFile, signFile, outputFile); err != nil {
				die("Failed: %v", err)
			}
			fmt.Fprintln(os.Stderr, "Done.")
		},
	}
	encryptCmd.Flags().StringVarP(&inputFile, "input", "i", "", "plaintext (use - for stdin)")
	encryptCmd.Flags().StringVarP(&outputFile, "output", "o", "", "cipher output (use - for stdout, default <input>.rsn)")
	encryptCmd.Flags().StringVarP(&signFile, "sign", "s", "", "signature output (use - for stdout, default <input>.sig)")
	rootCmd.AddCommand(encryptCmd)

	// ── decrypt ────────────────────────────────────────────────────────
	var decryptCmd = &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt file",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if pubKeyFile == "" {
				return errors.New("decrypt requires -K/--public-key")
			}
			if signFile == "" {
				return errors.New("decrypt requires -s/--sign")
			}
			if inputFile == "" {
				return errors.New("decrypt requires -i/--input")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			if outputFile == "" {
				if !isPipe(inputFile) && strings.HasSuffix(inputFile, ".rsn") {
					outputFile = strings.TrimSuffix(inputFile, ".rsn")
				} else {
					outputFile = "output.dec"
				}
			}
			if err := runDecrypt(pubKeyFile, signFile, inputFile, outputFile); err != nil {
				die("Failed: %v", err)
			}
			fmt.Fprintln(os.Stderr, "Done.")
		},
	}
	decryptCmd.Flags().StringVarP(&inputFile, "input", "i", "", "cipher file (use - for stdin)")
	decryptCmd.Flags().StringVarP(&signFile, "sign", "s", "", "signature file (use - for stdin)")
	decryptCmd.Flags().StringVarP(&outputFile, "output", "o", "", "plaintext output (use - for stdout, default strip .rsn)")
	rootCmd.AddCommand(decryptCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// ─── I/O helpers ─────────────────────────────────────────────────────────────

func isPipe(s string) bool { return s == "-" }

func defaultName(input, suffix, fallback string) string {
	if isPipe(input) {
		return fallback
	}
	return input + suffix
}

func readInput(path string) ([]byte, error) {
	if isPipe(path) {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func writeOutput(path string, data []byte) error {
	if isPipe(path) {
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// ─── command runners ─────────────────────────────────────────────────────────

func runGenKey(bits int, privOut, pubOut string) error {
	priv, pub, err := GenerateKeyPair(bits)
	if err != nil {
		return err
	}
	if err := WritePrivateKey(privOut, priv); err != nil {
		return err
	}
	return WritePublicKey(pubOut, pub)
}

func runEncrypt(privPath, plainPath, sigPath, cipherPath string) error {
	priv, err := ReadPrivateKey(privPath)
	if err != nil {
		return err
	}
	plaintext, err := readInput(plainPath)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	sig, ciphertext, err := EncryptCore(plaintext, priv)
	if err != nil {
		return err
	}
	if err := writeOutput(sigPath, sig); err != nil {
		return fmt.Errorf("write signature: %w", err)
	}
	if err := writeOutput(cipherPath, ciphertext); err != nil {
		return fmt.Errorf("write cipher: %w", err)
	}
	return nil
}

func runDecrypt(pubPath, sigPath, cipherPath, plainPath string) error {
	pub, err := ReadPublicKey(pubPath)
	if err != nil {
		return err
	}
	sig, err := readInput(sigPath)
	if err != nil {
		return fmt.Errorf("read signature: %w", err)
	}
	ciphertext, err := readInput(cipherPath)
	if err != nil {
		return fmt.Errorf("read cipher: %w", err)
	}
	plaintext, err := DecryptCore(sig, ciphertext, pub)
	if err != nil {
		return err
	}
	return writeOutput(plainPath, plaintext)
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", a...)
	os.Exit(1)
}
