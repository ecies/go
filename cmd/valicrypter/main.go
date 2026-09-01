// Command valicrypter is a tool to encrypt data to validators' secp256k1
// public keys using ecies.
package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/chronicleprotocol/ecies"
)

const usage = `Usage:
  valicrypter -r <pubkey-hex> <plaintext>              encrypt plaintext to a recipient, hex to stdout
  valicrypter -d -i <privkey-hex> <ciphertext-hex>     decrypt ciphertext, plaintext to stdout

Flags:
  -d              decrypt instead of encrypt
  -r <pubkey>     recipient public key, hex (33-byte compressed or 65-byte uncompressed)
  -i <privkey>    private key, hex; visible in shell history and process listings

Input starting with a dash must be preceded by --, as in:
  valicrypter -r <pubkey-hex> -- -plaintext
`

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "valicrypter: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("valicrypter", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	decrypt := fs.Bool("d", false, "decrypt instead of encrypt")
	recipient := fs.String("r", "", "recipient public key, hex")
	identity := fs.String("i", "", "private key, hex")

	if err := fs.Parse(args); err != nil {
		fmt.Fprint(os.Stderr, usage)
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	if *decrypt {
		if *recipient != "" {
			return fmt.Errorf("cannot use -r with -d: decryption takes a private key via -i")
		}
		if *identity == "" {
			return fmt.Errorf("missing -i: decryption requires a private key")
		}
	} else {
		if *identity != "" {
			return fmt.Errorf("cannot use -i without -d: encryption takes a public key via -r")
		}
		if *recipient == "" {
			return fmt.Errorf("missing -r: encryption requires a recipient public key")
		}
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("missing input argument")
	}
	if fs.NArg() > 1 {
		return fmt.Errorf("unexpected argument %q: input must be a single argument", fs.Arg(1))
	}

	if *decrypt {
		return runDecrypt(*identity, fs.Arg(0), stdout)
	}
	return runEncrypt(*recipient, fs.Arg(0), stdout)
}

func runEncrypt(recipient, plaintext string, w io.Writer) error {
	if plaintext == "" {
		return fmt.Errorf("empty input: nothing to encrypt")
	}

	pubkey, err := ecies.NewPublicKeyFromHex(trim0x(recipient))
	if err != nil {
		return fmt.Errorf("cannot parse recipient public key: %w", err)
	}

	ciphertext, err := ecies.Encrypt(pubkey, []byte(plaintext))
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(w, "%x\n", ciphertext)
	return err
}

func runDecrypt(identity, in string, w io.Writer) error {
	privkey, err := ecies.NewPrivateKeyFromHex(trim0x(identity))
	if err != nil {
		return fmt.Errorf("cannot parse private key: %w", err)
	}

	// Ciphertext pasted from a terminal or a file may carry stray whitespace.
	ciphertext, err := hex.DecodeString(trim0x(strings.TrimSpace(in)))
	if err != nil {
		return fmt.Errorf("cannot decode hex ciphertext: %w", err)
	}

	plaintext, err := ecies.Decrypt(privkey, ciphertext)
	if err != nil {
		return err
	}

	_, err = w.Write(plaintext)
	return err
}

// trim0x strips an optional leading 0x prefix.
func trim0x(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
}
