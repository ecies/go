package eciesgo

import (
	"bytes"
	"fmt"
	"math/big"
)

type Config struct {
	symmetricAlgorithm   string
	symmetricNonceLength int
}

var DEFAULT_CONFIG = Config{symmetricAlgorithm: "aes-256-gcm", symmetricNonceLength: 16}

// Encrypt encrypts a passed message with a receiver public key, returns ciphertext or encryption error
func EncryptConf(pubkey *PublicKey, msg []byte, config Config) ([]byte, error) {
	var ct bytes.Buffer

	// Generate ephemeral key
	ek, err := GenerateKey()
	if err != nil {
		return nil, err
	}

	ct.Write(ek.PublicKey.Bytes(false))

	// Derive shared secret
	ss, err := ek.Encapsulate(pubkey)
	if err != nil {
		return nil, err
	}

	// Symmetrical encryption
	ciphertext, err := EncryptSymm(ss, msg, config)
	if err != nil {
		return nil, err
	}

	ct.Write(ciphertext)
	return ct.Bytes(), nil
}

func Encrypt(pubkey *PublicKey, msg []byte) ([]byte, error) {
	return EncryptConf(pubkey, msg, DEFAULT_CONFIG)
}

// Decrypt decrypts a passed message with a receiver private key, returns plaintext or decryption error
func DecryptConf(privkey *PrivateKey, msg []byte, config Config) ([]byte, error) {
	if len(msg) <= (1 + 32 + 32) {
		return nil, fmt.Errorf("invalid length of message")
	}

	// Ephemeral sender public key
	ethPubkey := &PublicKey{
		Curve: getCurve(),
		X:     new(big.Int).SetBytes(msg[1:33]),
		Y:     new(big.Int).SetBytes(msg[33:65]),
	}

	// Derive shared secret
	ss, err := ethPubkey.Decapsulate(privkey)
	if err != nil {
		return nil, err
	}

	// Shift message
	msg = msg[65:]

	// Symmetrical decryption
	plaintext, err := DecryptSymm(ss, msg, config)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func Decrypt(privkey *PrivateKey, msg []byte) ([]byte, error) {
	return DecryptConf(privkey, msg, DEFAULT_CONFIG)
}
